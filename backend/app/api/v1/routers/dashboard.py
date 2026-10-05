from fastapi import APIRouter, Depends

from app.api.v1.dependencies import get_current_user, get_dashboard_summary_use_case
from app.api.v1.schemas.dashboard import DashboardSummaryResponse
from app.application.use_cases.get_dashboard_summary import GetDashboardSummaryUseCase
from app.domain.entities.user import User

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get(
    "/summary",
    response_model=DashboardSummaryResponse,
    summary="Scan and finding statistics for the current user",
)
async def get_summary(
    current_user: User = Depends(get_current_user),
    use_case: GetDashboardSummaryUseCase = Depends(get_dashboard_summary_use_case),
) -> DashboardSummaryResponse:
    result = await use_case.execute(current_user.id)
    return DashboardSummaryResponse.from_dto(result)
