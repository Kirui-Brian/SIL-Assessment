"""JWT validation against Keycloak JWKS plus role checks. Identical in both services."""
import os
from dataclasses import dataclass
import jwt
from jwt import PyJWKClient
from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

ISSUER = os.environ["OIDC_ISSUER"]
AUDIENCE = os.getenv("OIDC_AUDIENCE", "account")
_jwks = PyJWKClient(os.environ["OIDC_JWKS_URL"], cache_keys=True, lifespan=300)
_bearer = HTTPBearer(auto_error=False)


@dataclass(frozen=True)
class Principal:
    username: str
    roles: frozenset


def principal(creds: HTTPAuthorizationCredentials | None = Depends(_bearer)) -> Principal:
    if creds is None:
        raise HTTPException(401, "missing bearer token", headers={"WWW-Authenticate": "Bearer"})
    try:
        key = _jwks.get_signing_key_from_jwt(creds.credentials).key
        verify_aud = AUDIENCE != "account"
        claims = jwt.decode(
            creds.credentials, key,
            algorithms=["RS256"],                       # never accept "none" or HS256 here
            audience=AUDIENCE if verify_aud else None,
            issuer=ISSUER,
            options={"require": ["exp", "iss"], "verify_aud": verify_aud},
        )
    except Exception:
        raise HTTPException(401, "invalid token", headers={"WWW-Authenticate": "Bearer"})
    roles = frozenset(claims.get("realm_access", {}).get("roles", []))
    return Principal(claims.get("preferred_username", "unknown"), roles)


def require_roles(*allowed: str):
    def dep(p: Principal = Depends(principal)) -> Principal:
        if not p.roles.intersection(allowed):
            raise HTTPException(403, "insufficient role")
        return p
    return dep
