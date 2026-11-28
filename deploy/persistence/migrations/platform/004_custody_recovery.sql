ALTER TABLE outbox
    ADD COLUMN recovery_failures integer NOT NULL DEFAULT 0 CHECK (recovery_failures BETWEEN 0 AND 5),
    ADD COLUMN gap_through bigint CHECK (gap_through > 0),
    ADD COLUMN absence_id uuid REFERENCES message_receipts,
    ADD COLUMN absence_expires_at timestamptz,
    ADD CHECK ((absence_id IS NULL) = (absence_expires_at IS NULL));

CREATE TABLE custody_attempts (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    operation_id uuid NOT NULL,
    recipient catalog_id NOT NULL,
    message_type text NOT NULL DEFAULT 'SUBMIT_INSTRUCTION' CHECK (message_type='SUBMIT_INSTRUCTION'),
    instruction_version integer NOT NULL DEFAULT 1,
    action text NOT NULL CHECK (action IN ('SUBMIT_INSTRUCTION','QUERY_INSTRUCTION')),
    started_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    request_id uuid UNIQUE,
    prepared_envelope bytea,
    authority_id uuid UNIQUE REFERENCES message_receipts,
    finished_at timestamptz,
    outcome text,
    code text,
    response_id uuid REFERENCES message_receipts,
    retry_delay_seconds double precision CHECK (retry_delay_seconds > 0),
    FOREIGN KEY (operation_id,recipient,message_type,instruction_version) REFERENCES outbox,
    CHECK ((finished_at IS NULL) = (outcome IS NULL)),
    CHECK (action='SUBMIT_INSTRUCTION' OR (prepared_envelope IS NULL AND authority_id IS NULL)),
    CHECK (prepared_envelope IS NULL OR request_id IS NOT NULL)
);
CREATE UNIQUE INDEX custody_one_open_attempt ON custody_attempts(operation_id,recipient)
    WHERE finished_at IS NULL;

-- The old worker left PENDING even after persisting a verified permanent error.
-- Only a custody receipt for this exact submit can prove such an outcome.
INSERT INTO custody_attempts(operation_id,recipient,action,request_id,prepared_envelope,started_at,
                             finished_at,outcome,code,response_id)
SELECT q.operation_id,q.recipient,q.message_type,request.message_id,q.prepared_envelope,
       coalesce(request.issued_at,clock_timestamp()),
       coalesce(reply.received_at,clock_timestamp()),
       CASE WHEN reply.code IN ('INVALID_SCHEMA','FORBIDDEN','IDEMPOTENCY_CONFLICT')
            THEN 'BLOCKED' ELSE 'LEGACY' END,
       reply.code,reply.message_id
FROM outbox q
CROSS JOIN LATERAL (SELECT convert_from(q.prepared_envelope,'UTF8')::jsonb->'protected' AS fields) wire
CROSS JOIN LATERAL (SELECT (wire.fields->>'messageId')::uuid AS message_id,
                           (wire.fields->>'issuedAt')::timestamptz AS issued_at) request
LEFT JOIN LATERAL (
    SELECT m.message_id,m.received_at,m.result->>'code' AS code
    FROM message_receipts m
    WHERE m.result->>'kind'='CUSTODY_RESPONSE'
      AND m.result->>'operationId'=q.operation_id::text
      AND m.result->>'requestMessageId'=request.message_id::text
      AND ((m.result->>'messageType'='ERROR' AND (m.result->>'status',m.result->>'code') IN (
          ('400','INVALID_SCHEMA'),('403','FORBIDDEN'),('409','IDEMPOTENCY_CONFLICT'),('503','UNAVAILABLE')))
          OR (m.result->>'messageType'='SUBMIT_INSTRUCTION_RESULT' AND m.result->>'status'='202'))
    ORDER BY (m.result->>'status' IN ('400','403','409')) DESC,m.received_at DESC,m.message_id
    LIMIT 1
) reply ON true
WHERE q.message_type='SUBMIT_INSTRUCTION' AND q.attempts>0;

UPDATE operations o
SET delivery_status=CASE WHEN a.outcome='BLOCKED' THEN 'BLOCKED' ELSE 'UNKNOWN' END,
    updated_at=clock_timestamp()
FROM custody_attempts a
WHERE o.id=a.operation_id AND o.delivery_status='PENDING';

UPDATE outbox q SET poll_after=clock_timestamp()
FROM operations o WHERE o.id=q.operation_id AND q.message_type='SUBMIT_INSTRUCTION'
    AND o.delivery_status='CONFIRMED' AND q.poll_after IS NULL
    AND (SELECT event->>'state' FROM operation_events WHERE operation_id=o.id
         ORDER BY sequence DESC LIMIT 1) NOT IN ('REJECTED','SETTLED','SETTLEMENT_FAILED');

GRANT UPDATE (next_attempt_at,recovery_failures,gap_through,absence_id,absence_expires_at) ON outbox TO platform;
GRANT SELECT,INSERT ON custody_attempts TO platform;
GRANT UPDATE (request_id,prepared_envelope,finished_at,outcome,code,response_id,retry_delay_seconds)
    ON custody_attempts TO platform;
