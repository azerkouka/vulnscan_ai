"""In-memory test doubles for the domain ports.

Used by every use-case unit test so those tests exercise real business logic
with zero DB, network, or slow crypto - per the project rule that the LLM and
vector store (and here, persistence/crypto) are always mocked in unit tests.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import replace
from datetime import UTC, datetime
from types import TracebackType
from uuid import UUID, uuid4

from app.domain.entities.finding import Finding
from app.domain.entities.knowledge_document import KnowledgeDocument, KnowledgeDocumentRecord
from app.domain.entities.refresh_token import RefreshToken
from app.domain.entities.scan import Scan, ScanFile
from app.domain.entities.user import User
from app.domain.exceptions import InvalidCredentialsError
from app.domain.ports.archive_extractor import ArchiveExtractor, ExtractedFile
from app.domain.ports.code_chunker import CodeChunker
from app.domain.ports.finding_repository import FindingRepository
from app.domain.ports.job_runner import JobRunner
from app.domain.ports.knowledge_document_repository import KnowledgeDocumentRepository
from app.domain.ports.knowledge_indexer import KnowledgeIndexer
from app.domain.ports.knowledge_retriever import KnowledgeRetriever, RetrievedKnowledge
from app.domain.ports.llm_analyzer import AnalyzedFinding, LLMAnalyzer
from app.domain.ports.password_hasher import PasswordHasher
from app.domain.ports.refresh_token_repository import RefreshTokenRepository
from app.domain.ports.scan_repository import ScanRepository
from app.domain.ports.source_storage import SourceStorage
from app.domain.ports.token_service import AccessTokenClaims, TokenService
from app.domain.ports.unit_of_work import UnitOfWork
from app.domain.ports.user_repository import UserRepository
from app.domain.source_text import split_lines
from app.domain.value_objects.code_chunk import ChunkKind, CodeChunk
from app.domain.value_objects.code_location import CodeLocation
from app.domain.value_objects.knowledge_source import KnowledgeSource
from app.domain.value_objects.scan_status import ScanStatus
from app.domain.value_objects.severity import Severity


class FakeUserRepository(UserRepository):
    def __init__(self) -> None:
        self.by_id: dict[UUID, User] = {}

    async def get_by_id(self, user_id: UUID) -> User | None:
        return self.by_id.get(user_id)

    async def get_by_email(self, email: str) -> User | None:
        return next((u for u in self.by_id.values() if u.email == email), None)

    async def add(self, user: User) -> None:
        self.by_id[user.id] = user


class FakeRefreshTokenRepository(RefreshTokenRepository):
    def __init__(self) -> None:
        self.by_id: dict[UUID, RefreshToken] = {}

    async def add(self, token: RefreshToken) -> None:
        self.by_id[token.id] = token

    async def get_by_token_hash(self, token_hash: str) -> RefreshToken | None:
        return next((t for t in self.by_id.values() if t.token_hash == token_hash), None)

    async def revoke(self, token_id: UUID, *, replaced_by_id: UUID | None = None) -> None:
        token = self.by_id[token_id]
        self.by_id[token_id] = RefreshToken(
            id=token.id,
            user_id=token.user_id,
            token_hash=token.token_hash,
            expires_at=token.expires_at,
            revoked_at=datetime.now(UTC),
            replaced_by_id=replaced_by_id,
            created_at=token.created_at,
        )

    async def revoke_all_for_user(self, user_id: UUID) -> None:
        for token_id, token in list(self.by_id.items()):
            if token.user_id == user_id and token.revoked_at is None:
                await self.revoke(token_id)


class FakeKnowledgeDocumentRepository(KnowledgeDocumentRepository):
    def __init__(self) -> None:
        self.by_external_id: dict[str, KnowledgeDocumentRecord] = {}

    async def upsert(self, record: KnowledgeDocumentRecord) -> None:
        self.by_external_id[record.external_id] = record

    async def get_by_external_id(self, external_id: str) -> KnowledgeDocumentRecord | None:
        return self.by_external_id.get(external_id)

    async def list(
        self, *, source: KnowledgeSource | None = None, limit: int = 50, offset: int = 0
    ) -> list[KnowledgeDocumentRecord]:
        records = sorted(self.by_external_id.values(), key=lambda r: r.external_id)
        if source is not None:
            records = [r for r in records if r.source == source]
        return records[offset : offset + limit]

    async def count(self, *, source: KnowledgeSource | None = None) -> int:
        if source is None:
            return len(self.by_external_id)
        return sum(1 for r in self.by_external_id.values() if r.source == source)

    async def get_content_hashes(self, source: KnowledgeSource | None = None) -> dict[str, str]:
        return {
            r.external_id: r.content_hash
            for r in self.by_external_id.values()
            if source is None or r.source == source
        }

    async def delete(self, external_id: str) -> None:
        self.by_external_id.pop(external_id, None)


class FakeKnowledgeIndexer(KnowledgeIndexer):
    def __init__(self) -> None:
        self.by_external_id: dict[str, KnowledgeDocument] = {}
        self.upsert_calls: list[list[str]] = []

    async def upsert(self, documents: Sequence[KnowledgeDocument]) -> None:
        self.upsert_calls.append([doc.external_id for doc in documents])
        for doc in documents:
            self.by_external_id[doc.external_id] = doc

    async def delete(self, external_ids: Sequence[str]) -> None:
        for external_id in external_ids:
            self.by_external_id.pop(external_id, None)

    async def count(self, source: KnowledgeSource | None = None) -> int:
        if source is None:
            return len(self.by_external_id)
        return sum(1 for d in self.by_external_id.values() if d.source == source)


class FakeKnowledgeRetriever(KnowledgeRetriever):
    """Backed by the same store a `FakeKnowledgeIndexer` writes to, so tests
    can index then immediately query without a real vector store."""

    def __init__(self, indexer: FakeKnowledgeIndexer | None = None) -> None:
        self._indexer = indexer or FakeKnowledgeIndexer()

    async def query(
        self, query_text: str, *, top_k: int = 5, source: KnowledgeSource | None = None
    ) -> list[RetrievedKnowledge]:
        docs = list(self._indexer.by_external_id.values())
        if source is not None:
            docs = [d for d in docs if d.source == source]
        return [
            RetrievedKnowledge(
                external_id=d.external_id,
                source=d.source,
                name=d.name,
                url=d.url,
                content=d.content,
                distance=0.0,
            )
            for d in docs[:top_k]
        ]

    async def exists(self, external_id: str) -> bool:
        return external_id in self._indexer.by_external_id


class FakeScanRepository(ScanRepository):
    def __init__(self) -> None:
        self.by_id: dict[UUID, Scan] = {}
        self.files_by_scan_id: dict[UUID, list[ScanFile]] = {}
        self.status_history: list[ScanStatus] = []
        """Every status written, in order - lets a test assert a scan went
        through RUNNING, not just where it ended up."""
        self.progress_history: list[int] = []

    async def add(self, scan: Scan, files: Sequence[ScanFile]) -> None:
        self.by_id[scan.id] = scan
        self.files_by_scan_id[scan.id] = list(files)
        self.status_history.append(scan.status)

    async def get_by_id(self, scan_id: UUID) -> Scan | None:
        return self.by_id.get(scan_id)

    async def list_for_user(self, user_id: UUID, *, limit: int = 20, offset: int = 0) -> list[Scan]:
        scans = sorted(
            (s for s in self.by_id.values() if s.user_id == user_id),
            key=lambda s: s.created_at,
            reverse=True,
        )
        return scans[offset : offset + limit]

    async def count_for_user(self, user_id: UUID) -> int:
        return sum(1 for s in self.by_id.values() if s.user_id == user_id)

    async def count_by_status_for_user(self, user_id: UUID) -> dict[ScanStatus, int]:
        counts: dict[ScanStatus, int] = {}
        for scan in self.by_id.values():
            if scan.user_id == user_id:
                counts[scan.status] = counts.get(scan.status, 0) + 1
        return counts

    async def list_files(self, scan_id: UUID) -> list[ScanFile]:
        return sorted(self.files_by_scan_id.get(scan_id, []), key=lambda f: f.relative_path)

    async def update(self, scan: Scan) -> None:
        self.by_id[scan.id] = scan
        self.status_history.append(scan.status)
        self.progress_history.append(scan.progress_percent)

    async def delete(self, scan_id: UUID) -> None:
        self.by_id.pop(scan_id, None)
        self.files_by_scan_id.pop(scan_id, None)

    async def fail_unfinished(self, error_message: str) -> int:
        unfinished = [
            s for s in self.by_id.values() if s.status in (ScanStatus.PENDING, ScanStatus.RUNNING)
        ]
        for scan in unfinished:
            self.by_id[scan.id] = replace(
                scan,
                status=ScanStatus.FAILED,
                error_message=error_message,
                completed_at=datetime.now(UTC),
            )
        return len(unfinished)


class FakeFindingRepository(FindingRepository):
    def __init__(self, scans: FakeScanRepository | None = None) -> None:
        self.findings: list[Finding] = []
        self._scans = scans
        """Needed only by the per-user aggregates, to know whose scan a
        finding belongs to."""

    async def add_many(self, findings: Sequence[Finding]) -> None:
        self.findings.extend(findings)

    async def list_for_scan(self, scan_id: UUID) -> list[Finding]:
        return [f for f in self.findings if f.scan_id == scan_id]

    def _for_user(self, user_id: UUID) -> list[Finding]:
        scans = self._scans.by_id if self._scans is not None else {}
        return [
            f for f in self.findings if f.scan_id in scans and scans[f.scan_id].user_id == user_id
        ]

    async def count_by_severity_for_user(self, user_id: UUID) -> dict[Severity, int]:
        counts: dict[Severity, int] = {}
        for finding in self._for_user(user_id):
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        return counts

    async def top_cwes_for_user(self, user_id: UUID, *, limit: int = 5) -> list[tuple[str, int]]:
        counts: dict[str, int] = {}
        for finding in self._for_user(user_id):
            if finding.cwe_id is not None:
                counts[finding.cwe_id] = counts.get(finding.cwe_id, 0) + 1
        return sorted(counts.items(), key=lambda item: (-item[1], item[0]))[:limit]


class FakeSourceStorage(SourceStorage):
    def __init__(self) -> None:
        self.contents: dict[tuple[UUID, UUID], str] = {}
        self.deleted_scan_ids: list[UUID] = []

    async def save(self, scan_id: UUID, file_id: UUID, content: str) -> None:
        self.contents[(scan_id, file_id)] = content

    async def read(self, scan_id: UUID, file_id: UUID) -> str:
        return self.contents[(scan_id, file_id)]

    async def delete_scan(self, scan_id: UUID) -> None:
        self.deleted_scan_ids.append(scan_id)
        for key in [key for key in self.contents if key[0] == scan_id]:
            del self.contents[key]


class FakeArchiveExtractor(ArchiveExtractor):
    def __init__(self, files: Sequence[ExtractedFile] = (), error: Exception | None = None) -> None:
        self._files = list(files)
        self._error = error
        self.archives: list[bytes] = []

    def extract(self, archive: bytes) -> list[ExtractedFile]:
        self.archives.append(archive)
        if self._error is not None:
            raise self._error
        return list(self._files)


class FakeJobRunner(JobRunner):
    def __init__(self) -> None:
        self.enqueued_scan_ids: list[UUID] = []

    async def enqueue_scan(self, scan_id: UUID) -> None:
        self.enqueued_scan_ids.append(scan_id)


class FakeCodeChunker(CodeChunker):
    """Cuts a file into fixed-size line windows (the whole file by default) -
    predictable chunk boundaries, with no grammar needed."""

    def __init__(self, lines_per_chunk: int | None = None) -> None:
        self._lines_per_chunk = lines_per_chunk

    def supports(self, language: str) -> bool:
        return True

    def chunk(self, content: str, *, file_path: str, language: str) -> list[CodeChunk]:
        lines = split_lines(content)
        size = self._lines_per_chunk or max(len(lines), 1)
        return [
            CodeChunk(
                content="\n".join(lines[start : start + size]),
                language=language,
                location=CodeLocation(file_path, start + 1, min(start + size, len(lines))),
                kind=ChunkKind.MODULE,
            )
            for start in range(0, len(lines), size)
        ]


class FakeLLMAnalyzer(LLMAnalyzer):
    """Scripted stand-in for the LLM: each call consumes the next entry of
    `responses` (a list of findings to return, or an exception to raise);
    once they run out, every further call gives the default answer."""

    def __init__(
        self,
        responses: Sequence[list[AnalyzedFinding] | Exception] = (),
        default: Sequence[AnalyzedFinding] = (),
    ) -> None:
        self._responses = list(responses)
        self._default: list[AnalyzedFinding] | Exception = list(default)
        self.calls: list[tuple[CodeChunk, list[RetrievedKnowledge]]] = []

    def set_default(self, findings: Sequence[AnalyzedFinding]) -> None:
        self._default = list(findings)

    def set_default_error(self, error: Exception) -> None:
        self._default = error

    async def analyze(
        self, chunk: CodeChunk, context: list[RetrievedKnowledge]
    ) -> list[AnalyzedFinding]:
        self.calls.append((chunk, context))
        response = self._responses.pop(0) if self._responses else self._default
        if isinstance(response, Exception):
            raise response
        return list(response)


class FakeUnitOfWork(UnitOfWork):
    def __init__(self) -> None:
        self.users = FakeUserRepository()
        self.refresh_tokens = FakeRefreshTokenRepository()
        self.knowledge_documents = FakeKnowledgeDocumentRepository()
        self.scans = FakeScanRepository()
        self.findings = FakeFindingRepository(self.scans)
        self.committed = False

    async def __aenter__(self) -> FakeUnitOfWork:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        return None

    async def commit(self) -> None:
        self.committed = True

    async def rollback(self) -> None:
        self.committed = False


class FakePasswordHasher(PasswordHasher):
    """Not real crypto - just enough to unit-test use cases quickly."""

    _PREFIX = "hashed:"

    def hash(self, plain_password: str) -> str:
        return f"{self._PREFIX}{plain_password}"

    def verify(self, plain_password: str, hashed_password: str) -> bool:
        return hashed_password == f"{self._PREFIX}{plain_password}"


class FakeTokenService(TokenService):
    """Deterministic, in-memory stand-in for JWT + refresh token crypto."""

    def __init__(self) -> None:
        self._issued_access_tokens: dict[str, UUID] = {}
        self.next_refresh_value: str | None = None

    def create_access_token(self, user_id: UUID) -> str:
        token = f"access:{uuid4()}"
        self._issued_access_tokens[token] = user_id
        return token

    def decode_access_token(self, token: str) -> AccessTokenClaims:
        user_id = self._issued_access_tokens.get(token)
        if user_id is None:
            raise InvalidCredentialsError("Invalid or expired access token.")
        return AccessTokenClaims(user_id=user_id)

    def generate_refresh_token(self) -> str:
        return self.next_refresh_value or f"refresh:{uuid4()}"

    def hash_refresh_token(self, token_value: str) -> str:
        return f"hash:{token_value}"
