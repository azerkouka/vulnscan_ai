#!/usr/bin/env python
"""Records a finished demo scan, so the app has something to show before any
real scan has been run - useful for a demo, or when no model is installed.

It creates a demo account (if it doesn't exist yet) and one COMPLETED scan of
the deliberately vulnerable sample in `data/samples/vulnerable-app`, with
hand-written findings. Those findings are labelled as demo data in their
explanation: they were not produced by the model.

Usage:
    python -m scripts.seed_demo
    python -m scripts.seed_demo --email me@example.com --password 'a-strong-password'

When the account is created without --password, a random one is generated
and printed once. Running the script again adds another demo scan to the
same account and leaves its password untouched.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

from app.core.config import get_settings
from app.domain.entities.finding import Finding, FindingReference
from app.domain.entities.scan import Scan, ScanFile
from app.domain.entities.user import User
from app.domain.ports.unit_of_work import UnitOfWork
from app.domain.source_text import normalize_newlines, split_lines
from app.domain.value_objects.code_location import CodeLocation
from app.domain.value_objects.language import detect_language
from app.domain.value_objects.reference_source import ReferenceSource
from app.domain.value_objects.scan_status import ScanStatus
from app.domain.value_objects.severity import Severity
from app.domain.value_objects.source_type import SourceType
from app.infrastructure.persistence.database import create_engine, create_session_factory
from app.infrastructure.persistence.unit_of_work import SqlAlchemyUnitOfWork
from app.infrastructure.security.password_hasher import Argon2PasswordHasher
from app.infrastructure.uploads.local_source_storage import LocalSourceStorage

SAMPLE_DIR = Path("data/samples/vulnerable-app")
SAMPLE_FILES = ("app.py", "config.py", "web/server.js")
_DEMO_NOTE = " (Demo data: written by hand for the sample project, not produced by the model.)"


@dataclass(frozen=True, slots=True)
class DemoFinding:
    """A finding described by the line of code it is about, rather than by a
    line number that would silently go stale if the sample file were edited."""

    path: str
    marker: str
    """Text that appears on exactly one line of the file: the vulnerable line."""
    title: str
    severity: Severity
    confidence: float
    cwe_id: str | None
    owasp_category: str | None
    attack_technique_id: str | None
    explanation: str
    recommendation: str
    fixed_code: str | None


DEMO_FINDINGS: tuple[DemoFinding, ...] = (
    DemoFinding(
        path="app.py",
        marker='os.system("ping -c 1 " + host)',
        title="OS command injection",
        severity=Severity.CRITICAL,
        confidence=0.95,
        cwe_id="CWE-78",
        owasp_category="A03:2021",
        attack_technique_id="T1059",
        explanation=(
            "The `host` request parameter is concatenated into a shell command. A value "
            "such as `127.0.0.1; cat /etc/passwd` runs arbitrary commands on the server."
        ),
        recommendation=(
            "Run the program with an argument list and no shell, and validate the host "
            "against an allow-list or a strict pattern first."
        ),
        fixed_code='subprocess.run(["ping", "-c", "1", host], check=True)',
    ),
    DemoFinding(
        path="app.py",
        marker='query = "SELECT id, name, email FROM users WHERE name = \'" + name + "\'"',
        title="SQL injection",
        severity=Severity.HIGH,
        confidence=0.93,
        cwe_id="CWE-89",
        owasp_category="A03:2021",
        attack_technique_id="T1190",
        explanation=(
            "The query is assembled by concatenating the `name` request parameter, so the "
            "parameter can change the structure of the query (`' OR '1'='1`)."
        ),
        recommendation="Use a parameterized query and let the database driver bind the value.",
        fixed_code=(
            "rows = get_connection().execute(\n"
            '    "SELECT id, name, email FROM users WHERE name = ?", (name,)\n'
            ").fetchall()"
        ),
    ),
    DemoFinding(
        path="app.py",
        marker='return send_file(os.path.join("uploads", filename))',
        title="Path traversal in file download",
        severity=Severity.HIGH,
        confidence=0.88,
        cwe_id="CWE-22",
        owasp_category="A01:2021",
        attack_technique_id=None,
        explanation=(
            "The requested file name is joined to the uploads folder without checking "
            "the result, so `../../etc/passwd` reads files outside that folder."
        ),
        recommendation=(
            "Resolve the final path and refuse it unless it is still inside the uploads "
            "folder, or use a helper that enforces this."
        ),
        fixed_code='return send_from_directory("uploads", filename)',
    ),
    DemoFinding(
        path="web/server.js",
        marker="const result = eval(req.query.expression);",
        title="Code injection through eval",
        severity=Severity.CRITICAL,
        confidence=0.96,
        cwe_id="CWE-94",
        owasp_category="A03:2021",
        attack_technique_id="T1059",
        explanation=(
            "Request input is passed to `eval`, which executes it as JavaScript with the "
            "full privileges of the server process."
        ),
        recommendation=(
            "Never evaluate user input. Parse the expression with a dedicated, "
            "sandboxed expression parser instead."
        ),
        fixed_code=None,
    ),
    DemoFinding(
        path="web/server.js",
        marker="res.send('<h1>Hello ' + req.query.name + '</h1>');",
        title="Reflected cross-site scripting",
        severity=Severity.MEDIUM,
        confidence=0.9,
        cwe_id="CWE-79",
        owasp_category="A03:2021",
        attack_technique_id=None,
        explanation=(
            "The `name` parameter is written into the HTML response without escaping, "
            "so a crafted link runs script in the victim's browser."
        ),
        recommendation="Escape the value for HTML, or render it through a template engine that does.",
        fixed_code="res.send('<h1>Hello ' + escapeHtml(req.query.name) + '</h1>');",
    ),
    DemoFinding(
        path="config.py",
        marker='DATABASE_PASSWORD = "example-hardcoded-password"',
        title="Hardcoded database password",
        severity=Severity.MEDIUM,
        confidence=0.85,
        cwe_id="CWE-798",
        owasp_category="A07:2021",
        attack_technique_id=None,
        explanation=(
            "A credential is committed in source code, where everyone with read access "
            "to the repository - and its whole history - can recover it."
        ),
        recommendation=(
            "Load the secret from the environment or a secrets manager, and rotate the "
            "exposed value."
        ),
        fixed_code='DATABASE_PASSWORD = os.environ["DATABASE_PASSWORD"]',
    ),
    DemoFinding(
        path="config.py",
        marker="DEBUG = True",
        title="Debug mode enabled",
        severity=Severity.LOW,
        confidence=0.7,
        cwe_id="CWE-489",
        owasp_category="A05:2021",
        attack_technique_id=None,
        explanation=(
            "With debug mode on, errors return stack traces and, in some frameworks, an "
            "interactive console that executes code."
        ),
        recommendation="Turn debug mode off outside local development, driven by configuration.",
        fixed_code='DEBUG = os.environ.get("DEBUG") == "1"',
    ),
)


def load_sample_sources(sample_dir: Path = SAMPLE_DIR) -> dict[str, str]:
    """Relative path -> content, for each sample file."""
    return {
        path: normalize_newlines((sample_dir / path).read_text(encoding="utf-8"))
        for path in SAMPLE_FILES
    }


def locate(content: str, marker: str) -> int:
    """The 1-based number of the single line of `content` containing `marker`."""
    matches = [
        number for number, line in enumerate(split_lines(content), start=1) if marker in line
    ]
    if len(matches) != 1:
        raise ValueError(f"Expected exactly one line containing {marker!r}, found {len(matches)}.")
    return matches[0]


def build_demo_scan(
    user_id: UUID, sources: dict[str, str], now: datetime
) -> tuple[Scan, list[ScanFile], list[tuple[DemoFinding, int]]]:
    """The scan row, its files, and each demo finding with its line number."""
    scan_id = uuid4()
    files = [
        ScanFile(
            id=uuid4(),
            scan_id=scan_id,
            filename=Path(path).name,
            relative_path=path,
            language=detect_language(path),
            size_bytes=len(content.encode("utf-8")),
            content_hash=hashlib.sha256(content.encode("utf-8")).hexdigest(),
            loc=len(split_lines(content)),
        )
        for path, content in sources.items()
    ]
    located = [(demo, locate(sources[demo.path], demo.marker)) for demo in DEMO_FINDINGS]
    scan = Scan(
        id=scan_id,
        user_id=user_id,
        source_type=SourceType.ZIP,
        status=ScanStatus.COMPLETED,
        progress_percent=100,
        error_message=None,
        total_files=len(files),
        total_findings=len(located),
        created_at=now - timedelta(minutes=3),
        started_at=now - timedelta(minutes=3),
        completed_at=now,
    )
    return scan, files, located


async def _references(uow: UnitOfWork, demo: DemoFinding) -> list[FindingReference]:
    """Only ids that exist in the ingested knowledge base are cited - the same
    rule the real pipeline applies to what the model says."""
    references: list[FindingReference] = []
    candidates = (
        (ReferenceSource.CWE, demo.cwe_id),
        (ReferenceSource.OWASP, demo.owasp_category),
        (ReferenceSource.ATTACK, demo.attack_technique_id),
    )
    for source, external_id in candidates:
        if external_id is None:
            continue
        record = await uow.knowledge_documents.get_by_external_id(external_id)
        if record is not None:
            references.append(FindingReference(source, external_id, record.name, record.url))
    return references


async def seed(email: str, password: str | None) -> None:
    settings = get_settings()
    sources = load_sample_sources()
    engine = create_engine(settings.database_url)
    storage = LocalSourceStorage(Path(settings.upload_dir))
    now = datetime.now(UTC)

    try:
        async with create_session_factory(engine)() as session:
            uow = SqlAlchemyUnitOfWork(session)

            user = await uow.users.get_by_email(email)
            if user is None:
                generated = password is None
                password = password or secrets.token_urlsafe(18)
                user = User(
                    id=uuid4(),
                    email=email,
                    hashed_password=Argon2PasswordHasher().hash(password),
                    full_name="Demo User",
                    is_active=True,
                    is_superuser=False,
                    created_at=now,
                    updated_at=now,
                )
                await uow.users.add(user)
                await session.flush()
                print(f"Created account {email}")
                if generated:
                    print(f"  password (shown only now): {password}")
            else:
                print(f"Using existing account {email} (password unchanged)")

            scan, files, located = build_demo_scan(user.id, sources, now)
            for file in files:
                await storage.save(scan.id, file.id, sources[file.relative_path])
            await uow.scans.add(scan, files)

            file_ids = {file.relative_path: file.id for file in files}
            findings: list[Finding] = []
            for demo, line in located:
                references = await _references(uow, demo)
                cited = {reference.source: reference.ref_id for reference in references}
                findings.append(
                    Finding(
                        id=uuid4(),
                        scan_id=scan.id,
                        scan_file_id=file_ids[demo.path],
                        title=demo.title,
                        cwe_id=cited.get(ReferenceSource.CWE),
                        owasp_category=cited.get(ReferenceSource.OWASP),
                        attack_technique_id=cited.get(ReferenceSource.ATTACK),
                        severity=demo.severity,
                        confidence=demo.confidence,
                        location=CodeLocation(demo.path, line, line),
                        vulnerable_snippet=split_lines(sources[demo.path])[line - 1],
                        explanation=demo.explanation + _DEMO_NOTE,
                        recommendation=demo.recommendation,
                        fixed_code=demo.fixed_code,
                        references=references,
                        created_at=now,
                    )
                )
            await uow.findings.add_many(findings)
            await uow.commit()
    finally:
        await engine.dispose()

    classified = sum(1 for finding in findings if finding.references)
    print(f"Recorded demo scan {scan.id}: {len(files)} files, {len(findings)} findings")
    if classified < len(findings):
        print(
            f"  {len(findings) - classified} finding(s) have no CWE/OWASP/ATT&CK reference: "
            "run `python -m scripts.ingest_knowledge` first to get them."
        )


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--email", default="demo@example.com", help="Account to add the scan to.")
    parser.add_argument(
        "--password",
        default=None,
        help="Password for the account if it has to be created (default: a random one, printed).",
    )
    args = parser.parse_args()

    asyncio.run(seed(args.email.strip().lower(), args.password))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
