"""Host-side witnesses. Operator changes are isolated fixtures, never service code."""
from uuid import UUID


def verify(scenario, compose, db):
    def client(*args):
        compose(scenario, 'run', '--rm', '-T', 'manager', 'python', 'tests/platform/exchanges.py', *args)

    def sql(statement, role='platform'):
        return db.query(scenario, role, 'platform', statement)

    def counts():
        return sql('SELECT (SELECT count(*) FROM operations),(SELECT count(*) FROM operation_events),'
                   '(SELECT count(*) FROM outbox),(SELECT count(*) FROM message_receipts)')

    client('first')
    assert counts() == '10|20|3|16', counts()
    assert sql("SELECT count(*) FROM outbox q JOIN operations o ON o.id=q.operation_id "
               "WHERE q.payload=jsonb_build_object('boleta',o.boleta,'managerId',o.manager_id) "
               "AND q.recipient=o.boleta->>'custodianId' AND q.attempts=0 "
               "AND o.client_order_id IN ('ROUND','OP-000001')") == '2'
    db.query(scenario, 'platform', 'platform', 'DELETE FROM operation_events', reject='42501')
    db.query(scenario, 'platform', 'platform', "UPDATE operations SET boleta='{}'", reject='42501')
    op = str(UUID(sql("SELECT id FROM operations WHERE client_order_id='OP-000001'")))
    # Even the SELECT used for ownership would fail. The mismatch is rejected
    # before that read regardless of which UUID actually exists.
    sql('REVOKE SELECT ON operations FROM platform', 'postgres')
    client('route', op)
    sql('GRANT SELECT ON operations TO platform', 'postgres')
    assert counts() == '10|20|3|16', counts()
    # Simulate a newly committed projection only; no sender or custodian is required.
    sql(f"""INSERT INTO operation_events(operation_id,event)
        SELECT operation_id, event || jsonb_build_object('eventId',gen_random_uuid(),'sequence',3,
        'previousState','VALIDATED','state','SENT') FROM operation_events
        WHERE operation_id='{op}' AND sequence=2""", 'postgres')
    compose(scenario, 'restart', 'platform')
    client('advanced', op)
    # Force the last write to fail; neither preceding events nor intent may survive.
    sql('REVOKE INSERT ON message_receipts FROM platform', 'postgres')
    client('rollback')
    assert counts() == '10|21|3|18', counts()
    foreign = sql("""INSERT INTO operations(id,manager_id,boleta,digest)
        SELECT gen_random_uuid(),'OTHER',boleta,digest FROM operations WHERE id='%s' RETURNING id""" % op,
        'postgres')
    client('foreign', str(UUID(foreign)))
    sql('GRANT INSERT ON message_receipts TO platform; DELETE FROM portfolio_access', 'postgres')
    client('forbidden', op)
    assert counts() == '11|21|3|18', counts()
    logs = compose(scenario, 'logs', '--no-log-prefix', 'platform', capture_output=True, text=True).stdout
    assert 'exchange_failed' not in logs
    assert not any(marker in logs for marker in ('PRIVATE KEY', 'BEGIN CERTIFICATE', '980.500000',
                   'OP-000001', 'signatures', 'password', 'Traceback', 'ROLLBACK'))
    print('PASS PostgreSQL counts 10/20/3/16 then 10/21/3/18; append-only, current snapshot after restart, '
          'immutable creation result, atomic rollback, denied existing resource, sanitized logs; 0 skips')
