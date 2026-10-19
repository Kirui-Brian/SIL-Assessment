import json, logging, os, sys, time
from contextlib import contextmanager
import psycopg2, psycopg2.extras
from fastapi import Depends, FastAPI, HTTPException, Query, Request
from pydantic import BaseModel, Field
from auth import Principal, require_roles

app = FastAPI(title="Patients API", docs_url=None, redoc_url=None,
              openapi_url="/patients/openapi.json")   # demo/CI only: remove or protect in production   # docs disabled outside CI
log = logging.getLogger("audit")
logging.basicConfig(stream=sys.stdout, level=logging.INFO, format="%(message)s")


def audit(request: Request, who: Principal, action: str, **extra):
    log.info(json.dumps({"ts": time.time(), "svc": "patients", "event": "phi_access", "user": who.username,
                         "action": action, "request_id": request.headers.get("x-request-id"), **extra}))


@contextmanager
def db():
    conn = psycopg2.connect(os.environ["DB_DSN"], connect_timeout=5)
    try:
        yield conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        conn.commit()
    finally:
        conn.close()


class NewPatient(BaseModel):
    full_name: str = Field(min_length=2, max_length=120)
    national_id: str = Field(pattern=r"^\d{7,8}$")
    dob: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}$")
    phone: str | None = Field(default=None, pattern=r"^\+254[17]\d{8}$")
    diagnosis: str | None = Field(default=None, max_length=500)


def mask(row: dict, who: Principal) -> dict:
    if "clinician" in who.roles:
        return row
    # Data minimisation: reception sees only what scheduling needs.
    return {"id": row["id"], "full_name": row["full_name"],
            "national_id": "****" + row["national_id"][-3:], "phone": row["phone"]}


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


@app.get("/patients/{patient_id}")
def get_patient(patient_id: int, request: Request, who: Principal = Depends(require_roles("clinician", "receptionist"))):
    with db() as cur:
        cur.execute("SELECT id, full_name, national_id, dob::text, phone, diagnosis FROM patients WHERE id = %s", (patient_id,))
        row = cur.fetchone()
    if not row:
        raise HTTPException(404, "not found")
    audit(request, who, "read", patient_id=patient_id)
    return mask(row, who)


@app.get("/patients")
def list_patients(request: Request, limit: int = Query(20, ge=1, le=50), who: Principal = Depends(require_roles("clinician"))):
    with db() as cur:
        cur.execute("SELECT id, full_name, national_id, dob::text, phone, diagnosis FROM patients ORDER BY id LIMIT %s", (limit,))
        rows = cur.fetchall()
    audit(request, who, "list", count=len(rows))
    return rows


@app.post("/patients", status_code=201)
def create_patient(body: NewPatient, request: Request, who: Principal = Depends(require_roles("clinician"))):
    with db() as cur:
        cur.execute(
            "INSERT INTO patients (full_name, national_id, dob, phone, diagnosis, created_by) VALUES (%s,%s,%s,%s,%s,%s) RETURNING id",
            (body.full_name, body.national_id, body.dob, body.phone, body.diagnosis, who.username))
        new_id = cur.fetchone()["id"]
    audit(request, who, "create", patient_id=new_id)
    return {"id": new_id}
