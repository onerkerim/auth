from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.deps import get_db, get_current_active_superuser
from app.core.exceptions import NotFoundException

from app.schemas.user import RoleCreate, RoleRead




router = APIRouter()


@router.post("/", response_model=RoleRead, status_code=status.HTTP_201_CREATED)
def create_role(
    *,
    db: Session = Depends(get_db),
    role_in: RoleCreate,
    current_user: Any = Depends(get_current_active_superuser),
) -> Any:
    """
    Create new role.
    """
    role = db.query(Role).filter(Role.name == role_in.name).first()
    if role:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="The role with this name already exists in the system.",
        )
    role = Role(**role_in.dict())
    db.add(role)
    db.commit()
    db.refresh(role)
    return role


@router.get("/{role_id}", response_model=RoleRead)
def get_role_by_id(
    *,
    db: Session = Depends(get_db),
    role_id: int,
    current_user: Any = Depends(get_current_active_superuser),
) -> Any:
    """
    Get a specific role by ID.
    """
    role = db.query(Role).filter(Role.id == role_id).first()
    if not role:
        raise NotFoundException(detail="Role not found")
    return role


@router.get("/", response_model=list[RoleRead])
def get_all_roles(
    *,
    db: Session = Depends(get_db),
    current_user: Any = Depends(get_current_active_superuser),
) -> Any:
    """
    Get all roles.
    """
    roles = db.query(Role).all()
    return roles