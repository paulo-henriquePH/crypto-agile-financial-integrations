CREATE TABLE operation_snapshots (
    operation_id uuid NOT NULL,
    instruction_version integer NOT NULL CHECK (instruction_version=1),
    snapshot jsonb NOT NULL CHECK (
        (snapshot->>'state' IN ('SETTLED','SETTLEMENT_FAILED','REJECTED')) IS TRUE
    ),
    CHECK ((jsonb_typeof(snapshot->'sequence') = 'string'
            AND (snapshot->>'sequence') COLLATE "C" ~ '^[1-9][0-9]*$') IS TRUE),
    PRIMARY KEY (operation_id,instruction_version)
);

CREATE TABLE inbox (
    sender catalog_id NOT NULL,
    recipient catalog_id NOT NULL,
    message_type text NOT NULL CHECK (message_type='REGISTER_OPERATION'),
    operation_id uuid NOT NULL,
    instruction_version integer NOT NULL CHECK (instruction_version=1),
    digest bytea NOT NULL CHECK (octet_length(digest)=32),
    PRIMARY KEY(sender,recipient,message_type,operation_id,instruction_version),
    UNIQUE (operation_id,instruction_version),
    FOREIGN KEY (operation_id,instruction_version) REFERENCES operation_snapshots
);

CREATE TABLE message_receipts (
    message_id uuid PRIMARY KEY,
    digest bytea NOT NULL CHECK (octet_length(digest)=32),
    result jsonb NOT NULL,
    received_at timestamptz NOT NULL DEFAULT now()
);

GRANT SELECT,INSERT ON operation_snapshots,inbox,message_receipts TO administrator;
