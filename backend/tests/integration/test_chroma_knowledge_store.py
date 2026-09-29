import pytest

from app.domain.entities.knowledge_document import KnowledgeDocument
from app.domain.value_objects.knowledge_source import KnowledgeSource

_SQLI = KnowledgeDocument(
    external_id="CWE-89",
    source=KnowledgeSource.CWE,
    name="SQL Injection",
    category="Weakness",
    url="https://cwe.mitre.org/data/definitions/89.html",
    content=(
        "Improper Neutralization of Special Elements used in an SQL Command. "
        "The product constructs an SQL query using untrusted, externally-influenced "
        "input without escaping or parameterizing it, allowing an attacker to alter "
        "the query's meaning and read or modify arbitrary database records."
    ),
)
_XSS = KnowledgeDocument(
    external_id="CWE-79",
    source=KnowledgeSource.CWE,
    name="Cross-site Scripting",
    category="Weakness",
    url="https://cwe.mitre.org/data/definitions/79.html",
    content=(
        "Improper Neutralization of Input During Web Page Generation. The product "
        "does not neutralize user-controllable input before placing it in web page "
        "output, allowing an attacker to run script in a victim's browser."
    ),
)
_SSRF_OWASP = KnowledgeDocument(
    external_id="A10:2021",
    source=KnowledgeSource.OWASP,
    name="Server-Side Request Forgery",
    category="Server-Side Request Forgery",
    url="https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
    content="SSRF flaws occur when a web application fetches a remote resource without validating the user-supplied URL.",
)


@pytest.mark.integration
async def test_query_surfaces_the_semantically_relevant_document(chroma_store) -> None:
    await chroma_store.upsert([_SQLI, _XSS])

    results = await chroma_store.query(
        "user input concatenated directly into a database query string", top_k=2
    )

    assert {r.external_id for r in results} == {"CWE-89", "CWE-79"}
    by_id = {r.external_id: r for r in results}
    assert by_id["CWE-89"].distance < by_id["CWE-79"].distance
    assert by_id["CWE-89"].name == "SQL Injection"


@pytest.mark.integration
async def test_source_filter_excludes_other_sources(chroma_store) -> None:
    await chroma_store.upsert([_SQLI, _SSRF_OWASP])

    results = await chroma_store.query("injection", top_k=5, source=KnowledgeSource.OWASP)

    assert {r.external_id for r in results} == {"A10:2021"}


@pytest.mark.integration
async def test_exists_true_for_indexed_false_for_unknown(chroma_store) -> None:
    await chroma_store.upsert([_SQLI])

    assert await chroma_store.exists("CWE-89") is True
    assert await chroma_store.exists("CWE-999") is False


@pytest.mark.integration
async def test_count_reflects_upserts_and_deletes(chroma_store) -> None:
    assert await chroma_store.count() == 0

    await chroma_store.upsert([_SQLI, _XSS])
    assert await chroma_store.count() == 2
    assert await chroma_store.count(KnowledgeSource.CWE) == 2
    assert await chroma_store.count(KnowledgeSource.OWASP) == 0

    await chroma_store.delete(["CWE-89"])
    assert await chroma_store.count() == 1
    assert await chroma_store.exists("CWE-89") is False


@pytest.mark.integration
async def test_upsert_is_idempotent_and_overwrites_content(chroma_store) -> None:
    await chroma_store.upsert([_SQLI])
    revised = KnowledgeDocument(
        external_id=_SQLI.external_id,
        source=_SQLI.source,
        name="SQL Injection (revised)",
        category=_SQLI.category,
        url=_SQLI.url,
        content=_SQLI.content,
    )

    await chroma_store.upsert([revised])

    assert await chroma_store.count() == 1
    results = await chroma_store.query("SQL", top_k=1)
    assert results[0].name == "SQL Injection (revised)"
