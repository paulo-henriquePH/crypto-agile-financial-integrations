CREATE TABLE operations (
    id uuid PRIMARY KEY,
    manager_id catalog_id NOT NULL,
    boleta jsonb NOT NULL,
    client_order_id text GENERATED ALWAYS AS (boleta->>'clientOrderId') STORED NOT NULL,
    digest bytea NOT NULL CHECK (octet_length(digest)=32),
    instruction_version integer NOT NULL DEFAULT 1 CHECK (instruction_version=1),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    delivery_status text NOT NULL DEFAULT 'PENDING',
    reconciliation_status text NOT NULL DEFAULT 'NOT_READY',
    UNIQUE (manager_id, client_order_id)
);
CREATE TABLE operation_events (
    operation_id uuid NOT NULL REFERENCES operations,
    event jsonb NOT NULL,
    sequence integer GENERATED ALWAYS AS ((event->>'sequence')::integer) STORED,
    PRIMARY KEY (operation_id,sequence),
    CHECK (event->>'operationId' = operation_id::text)
);
CREATE TABLE outbox (
    operation_id uuid REFERENCES operations,
    recipient catalog_id NOT NULL,
    message_type text NOT NULL,
    instruction_version integer NOT NULL CHECK (instruction_version=1),
    payload jsonb NOT NULL,
    prepared_envelope bytea,
    attempts integer NOT NULL DEFAULT 0,
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY(operation_id,recipient,message_type,instruction_version)
);
CREATE TABLE message_receipts (
    message_id uuid PRIMARY KEY,
    digest bytea NOT NULL CHECK (octet_length(digest)=32),
    result jsonb NOT NULL,
    received_at timestamptz NOT NULL DEFAULT now()
);
GRANT INSERT,SELECT ON operations,operation_events,outbox,message_receipts TO platform;
