"""Deliberately flawed code of the kind AI assistants produce. SAST demo target only. Never deploy."""
import hashlib, random, jwt, requests
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True)


@app.get("/patients/{pid}")                      # no auth dependency at all
def get_patient(pid: str, cur=None):
    cur.execute(f"SELECT * FROM patients WHERE id = {pid}")   # SQL injection
    return cur.fetchone()


def make_reset_code():
    return random.randint(100000, 999999)         # predictable


def hash_pw(p):
    return hashlib.md5(p.encode()).hexdigest()    # weak


def read_claims(tok):
    return jwt.decode(tok, options={"verify_signature": False})   # trusts forged tokens


def call_partner(url):
    return requests.get(url, verify=False)         # TLS off
