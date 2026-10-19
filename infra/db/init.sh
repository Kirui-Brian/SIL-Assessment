#!/bin/sh
set -eu
sed -e "s/__PATIENTS_PW__/${PATIENTS_DB_PASSWORD}/" -e "s/__APPOINTMENTS_PW__/${APPOINTMENTS_DB_PASSWORD}/" \
  /docker-entrypoint-initdb.d/init.sql.tpl | psql -v ON_ERROR_STOP=1 -U postgres
