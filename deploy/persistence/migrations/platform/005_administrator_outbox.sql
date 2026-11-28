ALTER TABLE outbox ADD COLUMN administrator_status text,
    ADD CHECK (CASE WHEN message_type='REGISTER_OPERATION' THEN
        administrator_status IS NOT NULL AND administrator_status IN ('PENDING','UNKNOWN','CONFIRMED','BLOCKED')
        ELSE administrator_status IS NULL END);

-- No backfill: a terminal fact from before S2-12 cannot prove what was
-- independently registered in S2-11 or supply an atomic publication intent.
CREATE TABLE administrator_attempts (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    operation_id uuid NOT NULL,
    recipient catalog_id NOT NULL,
    message_type text NOT NULL DEFAULT 'REGISTER_OPERATION' CHECK (message_type='REGISTER_OPERATION'),
    instruction_version integer NOT NULL DEFAULT 1,
    action text NOT NULL CHECK (action IN ('REGISTER_OPERATION','QUERY_ADMIN_RECORD')),
    started_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    request_id uuid UNIQUE,
    prepared_envelope bytea,
    authority_id uuid UNIQUE REFERENCES message_receipts,
    finished_at timestamptz,
    outcome text CHECK (outcome IN ('CONFIRMED','NOT_FOUND','RETRY','BLOCKED')),
    code text,
    response_id uuid REFERENCES message_receipts,
    retry_delay_seconds double precision CHECK (retry_delay_seconds > 0),
    FOREIGN KEY (operation_id,recipient,message_type,instruction_version) REFERENCES outbox,
    CHECK ((finished_at IS NULL) = (outcome IS NULL)),
    CHECK (action='REGISTER_OPERATION' OR (prepared_envelope IS NULL AND authority_id IS NULL)),
    CHECK (prepared_envelope IS NULL OR request_id IS NOT NULL)
);
CREATE UNIQUE INDEX administrator_one_open_attempt ON administrator_attempts(operation_id,recipient)
    WHERE finished_at IS NULL;
GRANT UPDATE (administrator_status) ON outbox TO platform;
GRANT SELECT,INSERT ON administrator_attempts TO platform;
GRANT UPDATE (request_id,prepared_envelope,finished_at,outcome,code,response_id,retry_delay_seconds)
    ON administrator_attempts TO platform;
