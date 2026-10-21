"""
Attacks API router — CRUD operations and seeding for attack battery.
"""

import logging
import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.deps import get_db
from src.api.schemas import (
    AttackCreate,
    AttackListResponse,
    AttackResponse,
    AttackUpdate,
)
from src.attacks.categories import AttackCategory, Severity
from src.attacks.loader import load_yaml_seeds
from src.models.attack import Attack

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/attacks", tags=["Attacks"])


@router.get("", response_model=AttackListResponse)
async def list_attacks(
    db: Annotated[AsyncSession, Depends(get_db)],
    category: AttackCategory | None = Query(None, description="Filter by category"),
    severity: Severity | None = Query(None, description="Filter by severity"),
    source: str | None = Query(None, description="Filter by source"),
    enabled: bool | None = Query(None, description="Filter by enabled status"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
):
    """List attacks in the battery with optional filtering."""
    query = select(Attack)
    count_query = select(func.count()).select_from(Attack)

    if category:
        query = query.where(Attack.category == category)
        count_query = count_query.where(Attack.category == category)
    if severity:
        query = query.where(Attack.severity == severity)
        count_query = count_query.where(Attack.severity == severity)
    if source:
        query = query.where(Attack.source == source)
        count_query = count_query.where(Attack.source == source)
    if enabled is not None:
        query = query.where(Attack.enabled == enabled)
        count_query = count_query.where(Attack.enabled == enabled)

    total_res = await db.execute(count_query)
    total = total_res.scalar() or 0

    query = query.order_by(Attack.created_at.desc()).limit(limit).offset(offset)
    res = await db.execute(query)
    items = res.scalars().all()

    return AttackListResponse(total=total, items=list(items))


@router.get("/categories")
async def get_categories_summary(db: Annotated[AsyncSession, Depends(get_db)]):
    """Get attack categories and counts per category."""
    query = (
        select(Attack.category, func.count(Attack.id))
        .where(Attack.enabled == True)
        .group_by(Attack.category)
    )
    res = await db.execute(query)
    category_counts = {str(cat): count for cat, count in res.all()}

    # Ensure all enum categories are represented
    summary = []
    for cat in AttackCategory:
        summary.append({
            "category": cat.value,
            "count": category_counts.get(cat.value, category_counts.get(cat, 0)),
        })
    return {"categories": summary}


@router.get("/{attack_id}", response_model=AttackResponse)
async def get_attack(
    attack_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Retrieve an attack probe by ID."""
    res = await db.execute(select(Attack).where(Attack.id == attack_id))
    attack = res.scalar_one_or_none()
    if not attack:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Attack with ID {attack_id} not found",
        )
    return attack


@router.post("", response_model=AttackResponse, status_code=status.HTTP_201_CREATED)
async def create_attack(
    payload: AttackCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Create a new custom attack probe."""
    attack = Attack(
        id=uuid.uuid4(),
        name=payload.name,
        category=payload.category,
        severity=payload.severity,
        payload=payload.payload,
        expected_safe_behavior=payload.expected_safe_behavior,
        source=payload.source,
        metadata_json=payload.metadata_json,
        enabled=payload.enabled,
    )
    db.add(attack)
    await db.flush()
    return attack


@router.patch("/{attack_id}", response_model=AttackResponse)
async def update_attack(
    attack_id: uuid.UUID,
    update_data: AttackUpdate,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Update an attack probe."""
    res = await db.execute(select(Attack).where(Attack.id == attack_id))
    attack = res.scalar_one_or_none()
    if not attack:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Attack with ID {attack_id} not found",
        )

    for field, value in update_data.model_dump(exclude_unset=True).items():
        setattr(attack, field, value)

    await db.flush()
    return attack


@router.delete("/{attack_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_attack(
    attack_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Delete an attack from the battery."""
    res = await db.execute(select(Attack).where(Attack.id == attack_id))
    attack = res.scalar_one_or_none()
    if not attack:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Attack with ID {attack_id} not found",
        )
    await db.delete(attack)
    await db.flush()


@router.post("/seed", status_code=status.HTTP_200_OK)
async def seed_battery(
    db: Annotated[AsyncSession, Depends(get_db)],
    force_reload: bool = Query(False, description="Force reload existing seeds"),
):
    """Load or reload attack seed YAML files into the database."""
    loaded = await load_yaml_seeds(db, force_reload=force_reload)
    return {"message": f"Successfully loaded {loaded} attack seeds", "loaded": loaded}
