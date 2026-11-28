ALTER TABLE outbox ADD COLUMN poll_after timestamptz;
CREATE UNIQUE INDEX operation_event_identity
    ON operation_events (operation_id, ((event->>'eventId')::uuid));
CREATE TABLE custody_facts (
    operation_id uuid NOT NULL REFERENCES operations,
    event jsonb NOT NULL,
    sequence integer GENERATED ALWAYS AS ((event->>'sequence')::integer) STORED,
    event_id uuid GENERATED ALWAYS AS ((event->>'eventId')::uuid) STORED,
    PRIMARY KEY(operation_id,sequence),
    UNIQUE (operation_id,event_id),
    CHECK (event->>'operationId' = operation_id::text)
);
GRANT SELECT,INSERT ON custody_facts TO platform;
GRANT UPDATE (delivery_status,updated_at) ON operations TO platform;
GRANT UPDATE (prepared_envelope,attempts,poll_after) ON outbox TO platform;
