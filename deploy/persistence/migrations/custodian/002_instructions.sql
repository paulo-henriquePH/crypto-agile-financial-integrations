CREATE TABLE inbox (
    sender catalog_id NOT NULL,
    recipient catalog_id NOT NULL,
    message_type text NOT NULL CHECK (message_type='SUBMIT_INSTRUCTION'),
    operation_id uuid UNIQUE NOT NULL,
    instruction_version integer NOT NULL CHECK (instruction_version=1),
    digest bytea NOT NULL CHECK (octet_length(digest)=32),
    payload jsonb NOT NULL,
    result jsonb NOT NULL,
    PRIMARY KEY(sender,recipient,message_type,operation_id,instruction_version)
);
CREATE TABLE instruction_events (
    operation_id uuid NOT NULL REFERENCES inbox(operation_id),
    event jsonb NOT NULL,
    sequence integer GENERATED ALWAYS AS ((event->>'sequence')::integer) STORED,
    PRIMARY KEY(operation_id,sequence),
    CHECK (event->>'operationId'=operation_id::text)
);
CREATE TABLE message_receipts (
    message_id uuid PRIMARY KEY,
    digest bytea NOT NULL CHECK (octet_length(digest)=32),
    result jsonb NOT NULL,
    received_at timestamptz NOT NULL DEFAULT now()
);
GRANT SELECT,INSERT ON inbox,instruction_events,message_receipts TO custodian;
