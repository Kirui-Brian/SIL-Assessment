-- Synthetic data only. No real patient data ever enters dev or CI environments.
CREATE DATABASE clinic;
\c clinic

CREATE TABLE patients (
  id           SERIAL PRIMARY KEY,
  full_name    TEXT NOT NULL,
  national_id  TEXT NOT NULL,
  dob          DATE NOT NULL,
  phone        TEXT,
  diagnosis    TEXT,
  created_by   TEXT NOT NULL,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE appointments (
  id            SERIAL PRIMARY KEY,
  patient_id    INTEGER NOT NULL,          -- no FK on purpose: appointments_svc has no access to patients
  scheduled_at  TIMESTAMPTZ NOT NULL,
  clinician     TEXT NOT NULL,
  reason        TEXT,
  created_by    TEXT NOT NULL
);

INSERT INTO patients (full_name, national_id, dob, phone, diagnosis, created_by) VALUES
 ('Amina Wanjiru (synthetic)', '12345678', '1988-03-14', '+254700000001', 'Type 2 diabetes', 'seed'),
 ('Brian Otieno (synthetic)',  '23456789', '1975-11-02', '+254700000002', 'Hypertension',    'seed');
INSERT INTO appointments (patient_id, scheduled_at, clinician, reason, created_by) VALUES
 (1, now() + interval '2 days', 'alice', 'Follow-up', 'seed');

-- Least privilege: one DB role per service, table-scoped, no DDL, no cross-table access.
CREATE ROLE patients_svc      LOGIN PASSWORD '__PATIENTS_PW__';
CREATE ROLE appointments_svc  LOGIN PASSWORD '__APPOINTMENTS_PW__';
GRANT SELECT, INSERT ON patients TO patients_svc;
GRANT USAGE ON SEQUENCE patients_id_seq TO patients_svc;
GRANT SELECT, INSERT ON appointments TO appointments_svc;
GRANT USAGE ON SEQUENCE appointments_id_seq TO appointments_svc;
