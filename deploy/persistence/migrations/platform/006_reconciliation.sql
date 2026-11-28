CREATE TABLE custody_snapshots (
    operation_id uuid NOT NULL REFERENCES operations,
    instruction_version integer NOT NULL CHECK (instruction_version=1),
    revision integer NOT NULL,
    response_id uuid NOT NULL UNIQUE REFERENCES message_receipts,
    snapshot jsonb NOT NULL,
    PRIMARY KEY (operation_id,instruction_version,revision),
    CHECK ((revision>0 AND (snapshot->>'sequence')::integer=revision) IS TRUE)
);

CREATE TABLE reconciliation_jobs (
    operation_id uuid NOT NULL,
    instruction_version integer NOT NULL,
    custody_revision integer NOT NULL,
    next_attempt_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    failures integer NOT NULL DEFAULT 0 CHECK (failures BETWEEN 0 AND 5),
    work_status text NOT NULL DEFAULT 'PENDING' CHECK (work_status IN ('PENDING','DONE','BLOCKED')),
    last_code text,
    PRIMARY KEY (operation_id,instruction_version),
    UNIQUE (operation_id,instruction_version,custody_revision),
    FOREIGN KEY (operation_id,instruction_version,custody_revision) REFERENCES custody_snapshots
);
CREATE INDEX reconciliation_due ON reconciliation_jobs (next_attempt_at) WHERE work_status='PENDING';

CREATE TABLE reconciliation_results (
    operation_id uuid NOT NULL,
    instruction_version integer NOT NULL,
    custody_revision integer NOT NULL,
    checked_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    administrator_response_id uuid PRIMARY KEY REFERENCES message_receipts,
    manager_snapshot jsonb NOT NULL,
    manager_digest bytea NOT NULL CHECK (octet_length(manager_digest)=32),
    administrator_snapshot jsonb,
    -- SOAP sequence has no independent fixed digit limit. Keep it as text.
    administrator_revision text GENERATED ALWAYS AS (administrator_snapshot->>'sequence') STORED,
    status text NOT NULL CHECK (status IN ('NOT_READY','MATCHED','DIVERGENT')),
    differences jsonb NOT NULL CHECK (jsonb_typeof(differences)='array'),
    FOREIGN KEY (operation_id,instruction_version,custody_revision)
        REFERENCES reconciliation_jobs (operation_id,instruction_version,custody_revision),
    CHECK ((status='NOT_READY') = (administrator_snapshot IS NULL)),
    CHECK ((status='DIVERGENT') = (jsonb_array_length(differences)>0)),
    CHECK (administrator_snapshot IS NULL OR administrator_revision IS NOT NULL)
);
CREATE UNIQUE INDEX reconciliation_one_conclusion ON reconciliation_results (operation_id,instruction_version)
    WHERE status<>'NOT_READY';

ALTER TABLE operations ADD CHECK (reconciliation_status IN ('NOT_READY','MATCHED','DIVERGENT'));
GRANT SELECT,INSERT ON custody_snapshots,reconciliation_jobs,reconciliation_results TO platform;
GRANT UPDATE (work_status,failures,next_attempt_at,last_code) ON reconciliation_jobs TO platform;
GRANT UPDATE (reconciliation_status) ON operations TO platform;
