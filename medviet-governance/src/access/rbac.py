# src/access/rbac.py
import os
import casbin
from functools import wraps
from fastapi import HTTPException, Header, Depends
from typing import Optional

# Danh sách user giả lập (production dùng JWT + DB)
MOCK_USERS = {
    "token-alice": {"username": "alice", "role": "admin"},
    "token-bob":   {"username": "bob",   "role": "ml_engineer"},
    "token-carol": {"username": "carol", "role": "data_analyst"},
    "token-dave":  {"username": "dave",  "role": "intern"},
}

# Resolve paths relative to project root
_project_root = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
_policy_path = os.path.join(_project_root, "src", "access", "policy.csv")
_model_path = os.path.join(_project_root, "src", "access", "model.conf")

enforcer = casbin.Enforcer(_model_path, _policy_path)


def get_current_user(authorization: Optional[str] = Header(None)) -> dict:
    """
    Parse Bearer token và trả về user info.
    Raise HTTPException 401 nếu token không hợp lệ.
    """
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing token")

    token = authorization.split(" ")[1]
    user = MOCK_USERS.get(token)

    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")

    return user


def require_permission(resource: str, action: str):
    """
    Decorator kiểm tra RBAC permission.
    Dùng casbin enforcer để check (role, resource, action).
    Raise HTTPException 403 nếu không có quyền.
    """
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            current_user = kwargs.get("current_user")
            if current_user is None:
                current_user = kwargs.get(
                    "__current_user__"
                )

            role = current_user["role"]

            allowed = enforcer.enforce(role, resource, action)

            if not allowed:
                raise HTTPException(
                    status_code=403,
                    detail=f"Role '{role}' cannot '{action}' on '{resource}'"
                )
            return await func(*args, **kwargs)
        return wrapper
    return decorator
