"""In-memory test doubles for the domain ports.

Used by every use-case unit test so those tests exercise real business logic
with zero DB, network, or slow crypto - per the project rule that the LLM and
vector store (and here, persistence/crypto) are always mocked in unit tests.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime
from types import TracebackType
from uuid import UUID, uuid4

from app.domain.entities.knowledge_document import KnowledgeDocument, KnowledgeDocumentRecord
from app.domain.entities.refresh_token import RefreshToken
from app.domain.entities.user import User
from app.domain.exceptions import InvalidCredentialsError
from app.domain.ports.knowledge_document_repository import KnowledgeDocumentRepository
from app.domain.ports.knowledge_indexer import KnowledgeIndexer
from app.domain.ports.knowledge_retriever import KnowledgeRetriever, RetrievedKnowledge
from app.domain.ports.password_hasher import PasswordHasher
from app.domain.ports.refresh_token_repository import RefreshTokenRepository
from app.domain.ports.token_service import AccessTokenClaims, TokenService
from app.domain.ports.unit_of_work import UnitOfWork
from app.domain.ports.user_repository import UserRepository
from app.domain.value_objects.knowledge_source import KnowledgeSource


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


class FakeUnitOfWork(UnitOfWork):
    def __init__(self) -> None:
        self.users = FakeUserRepository()
        self.refresh_tokens = FakeRefreshTokenRepository()
        self.knowledge_documents = FakeKnowledgeDocumentRepository()
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
