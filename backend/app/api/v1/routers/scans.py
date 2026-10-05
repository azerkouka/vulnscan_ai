from uuid import UUID

from fastapi import APIRouter, Depends, File, Form, Query, Request, Response, UploadFile, status

from app.api.v1.dependencies import (
    get_create_scan_use_case,
    get_current_user,
    get_delete_scan_use_case,
    get_export_scan_report_use_case,
    get_get_scan_report_use_case,
    get_get_scan_use_case,
    get_list_scans_use_case,
)
from app.api.v1.schemas.scan import ScanListResponse, ScanReportResponse, ScanResponse
from app.application.dto.scan import CreateScanInput
from app.application.use_cases.create_scan import CreateScanUseCase
from app.application.use_cases.delete_scan import DeleteScanUseCase
from app.application.use_cases.export_scan_report import ExportScanReportUseCase
from app.application.use_cases.get_scan import GetScanUseCase
from app.application.use_cases.get_scan_report import GetScanReportUseCase
from app.application.use_cases.list_scans import ListScansUseCase
from app.core.config import Settings, get_settings
from app.core.exceptions import ValidationAppError
from app.core.rate_limit import limiter
from app.domain.entities.user import User
from app.domain.exceptions import SourceTooLargeError
from app.domain.value_objects.report_format import ReportFormat

router = APIRouter(prefix="/scans", tags=["scans"])

# Each accepted scan costs minutes of model time; see also the per-user cap
# on unfinished scans (`MAX_ACTIVE_SCANS_PER_USER`).
_scan_rate_limit = get_settings().scan_rate_limit


@router.post(
    "",
    response_model=ScanResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Submit source code for analysis",
    description=(
        "Send **either** `file` (one source file, or a `.zip` of a project) **or** `code` "
        "(a pasted snippet, optionally with its `language`). The scan is analyzed in the "
        "background: poll `GET /scans/{scan_id}` until its status is `COMPLETED` or `FAILED`."
    ),
)
@limiter.limit(_scan_rate_limit)
async def create_scan(
    request: Request,
    file: UploadFile | None = File(default=None),
    code: str | None = Form(default=None),
    language: str | None = Form(default=None),
    current_user: User = Depends(get_current_user),
    settings: Settings = Depends(get_settings),
    use_case: CreateScanUseCase = Depends(get_create_scan_use_case),
) -> ScanResponse:
    if (file is None) == (code is None):
        raise ValidationAppError("Provide exactly one of 'file' or 'code'.")

    if file is not None:
        # Read one byte past the limit and stop: enough to know the upload is
        # too large without pulling an arbitrarily big body into memory.
        max_bytes = settings.upload_max_size_mb * 1024 * 1024
        content = await file.read(max_bytes + 1)
        if len(content) > max_bytes:
            raise SourceTooLargeError(
                f"Uploaded file exceeds the {settings.upload_max_size_mb} MB limit."
            )
        data = CreateScanInput(
            user_id=current_user.id, content=content, filename=file.filename or ""
        )
    else:
        data = CreateScanInput(
            user_id=current_user.id, content=(code or "").encode("utf-8"), language=language
        )

    result = await use_case.execute(data)
    return ScanResponse.from_dto(result)


@router.get("", response_model=ScanListResponse, summary="List your scans, most recent first")
async def list_scans(
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    current_user: User = Depends(get_current_user),
    use_case: ListScansUseCase = Depends(get_list_scans_use_case),
) -> ScanListResponse:
    result = await use_case.execute(current_user.id, limit=limit, offset=offset)
    return ScanListResponse.from_dto(result, limit=limit, offset=offset)


@router.get("/{scan_id}", response_model=ScanResponse, summary="Get a scan's status and progress")
async def get_scan(
    scan_id: UUID,
    current_user: User = Depends(get_current_user),
    use_case: GetScanUseCase = Depends(get_get_scan_use_case),
) -> ScanResponse:
    result = await use_case.execute(current_user.id, scan_id)
    return ScanResponse.from_dto(result)


@router.get(
    "/{scan_id}/report",
    response_model=ScanReportResponse,
    summary="Get a scan's findings, most severe first",
)
async def get_scan_report(
    scan_id: UUID,
    current_user: User = Depends(get_current_user),
    use_case: GetScanReportUseCase = Depends(get_get_scan_report_use_case),
) -> ScanReportResponse:
    result = await use_case.execute(current_user.id, scan_id)
    return ScanReportResponse.from_dto(result)


@router.get(
    "/{scan_id}/export",
    summary="Download a finished scan's report as a JSON or PDF file",
    response_class=Response,
    responses={
        200: {
            "content": {"application/json": {}, "application/pdf": {}},
            "description": "The report, as a file download.",
        }
    },
)
async def export_scan_report(
    scan_id: UUID,
    report_format: ReportFormat = Query(default=ReportFormat.JSON, alias="format"),
    current_user: User = Depends(get_current_user),
    use_case: ExportScanReportUseCase = Depends(get_export_scan_report_use_case),
) -> Response:
    exported = await use_case.execute(current_user.id, scan_id, report_format)
    return Response(
        content=exported.content,
        media_type=exported.media_type,
        # The filename is built from the scan id only - nothing user-supplied.
        headers={"Content-Disposition": f'attachment; filename="{exported.filename}"'},
    )


@router.delete(
    "/{scan_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_model=None,
    summary="Delete a finished scan, its findings and its stored source",
)
async def delete_scan(
    scan_id: UUID,
    current_user: User = Depends(get_current_user),
    use_case: DeleteScanUseCase = Depends(get_delete_scan_use_case),
) -> None:
    await use_case.execute(current_user.id, scan_id)
