import json, logging, os, sys, time
from contextlib import contextmanager
from datetime import datetime
import psycopg2, psycopg2.extras
from fastapi import Depends, FastAPI, HTTPException, Query, Request
from pydantic import BaseModel, Field
from auth import Principal, require_roles

app = FastAPI(title="Appointments API", docs_url=None, redoc_url=None,
              openapi_url="/appointments/openapi.json")   # demo/CI only: remove or protect in production
log = logging.getLogger("audit")
logging.basicConfig(stream=sys.stdout, level=logging.INFO, format="%(message)s")


@contextmanager
def db():
    conn = psycopg2.connect(os.environ["DB_DSN"], connect_timeout=5)
    try:
        yield conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        conn.commit()
    finally:
        conn.close()


class NewAppointment(BaseModel):
    patient_id: int = Field(gt=0)
    scheduled_at: datetime
    clinician: str = Field(pattern=r"^[a-z][a-z0-9._-]{1,40}$")
    reason: str | None = Field(default=None, max_length=200)   # keep clinical detail out of this service


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


@app.get("/appointments")
def list_appointments(patient_id: int = Query(gt=0), who: Principal = Depends(require_roles("clinician", "receptionist"))):
    with db() as cur:
        cur.execute("SELECT id, patient_id, scheduled_at::text, clinician, reason FROM appointments WHERE patient_id = %s ORDER BY scheduled_at", (patient_id,))
        return cur.fetchall()


@app.post("/appointments", status_code=201)
def create_appointment(body: NewAppointment, request: Request, who: Principal = Depends(require_roles("clinician", "receptionist"))):
    if body.scheduled_at.timestamp() < time.time():
        raise HTTPException(422, "appointment must be in the future")
    with db() as cur:
        cur.execute("INSERT INTO appointments (patient_id, scheduled_at, clinician, reason, created_by) VALUES (%s,%s,%s,%s,%s) RETURNING id",
                    (body.patient_id, body.scheduled_at, body.clinician, body.reason, who.username))
        new_id = cur.fetchone()["id"]
    log.info(json.dumps({"ts": time.time(), "svc": "appointments", "event": "create", "user": who.username,
                         "id": new_id, "request_id": request.headers.get("x-request-id")}))
    return {"id": new_id}
