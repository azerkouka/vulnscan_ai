from pathlib import Path

from fastapi import APIRouter, Depends, Query

from app.api.v1.dependencies import (
    get_current_superuser,
    get_get_knowledge_document_use_case,
    get_ingest_knowledge_use_case,
    get_knowledge_health_use_case,
    get_list_knowledge_documents_use_case,
)
from app.api.v1.schemas.knowledge import (
    IngestRequest,
    IngestResponse,
    KnowledgeDocumentListResponse,
    KnowledgeDocumentResponse,
    KnowledgeHealthResponse,
)
from app.application.use_cases.get_knowledge_document import GetKnowledgeDocumentUseCase
from app.application.use_cases.get_knowledge_health import GetKnowledgeHealthUseCase
from app.application.use_cases.ingest_knowledge import IngestKnowledgeUseCase
from app.application.use_cases.list_knowledge_documents import (
    ListKnowledgeDocumentsInput,
    ListKnowledgeDocumentsUseCase,
)
from app.core.config import get_settings
from app.domain.entities.user import User
from app.domain.value_objects.knowledge_source import KnowledgeSource
from app.infrastructure.ingestion import load_documents

router = APIRouter(prefix="/knowledge", tags=["knowledge"])


@router.post(
    "/ingest",
    response_model=IngestResponse,
    summary="(Re-)ingest the security knowledge base into ChromaDB",
)
async def ingest(
    payload: IngestRequest,
    _admin: User = Depends(get_current_superuser),
    use_case: IngestKnowledgeUseCase = Depends(get_ingest_knowledge_use_case),
) -> IngestResponse:
    sources = payload.sources or list(KnowledgeSource)
    data_dir = Path(get_settings().knowledge_data_dir)
    documents = load_documents(sources, data_dir)

    result = await use_case.execute(documents)
    return IngestResponse.from_dto(result)


@router.get(
    "/documents",
    response_model=KnowledgeDocumentListResponse,
    summary="List ingested knowledge documents",
)
async def list_documents(
    source: KnowledgeSource | None = None,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    _admin: User = Depends(get_current_superuser),
    use_case: ListKnowledgeDocumentsUseCase = Depends(get_list_knowledge_documents_use_case),
) -> KnowledgeDocumentListResponse:
    result = await use_case.execute(
        ListKnowledgeDocumentsInput(source=source, limit=limit, offset=offset)
    )
    return KnowledgeDocumentListResponse.from_dto(result, limit=limit, offset=offset)


@router.get(
    "/documents/{external_id}",
    response_model=KnowledgeDocumentResponse,
    summary="Get one knowledge document by its external id (e.g. CWE-89)",
)
async def get_document(
    external_id: str,
    _admin: User = Depends(get_current_superuser),
    use_case: GetKnowledgeDocumentUseCase = Depends(get_get_knowledge_document_use_case),
) -> KnowledgeDocumentResponse:
    result = await use_case.execute(external_id)
    return KnowledgeDocumentResponse.from_dto(result)


@router.get(
    "/health",
    response_model=KnowledgeHealthResponse,
    summary="Vector store document counts per source",
)
async def health(
    _admin: User = Depends(get_current_superuser),
    use_case: GetKnowledgeHealthUseCase = Depends(get_knowledge_health_use_case),
) -> KnowledgeHealthResponse:
    result = await use_case.execute()
    return KnowledgeHealthResponse.from_dto(result)
