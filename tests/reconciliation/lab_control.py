"""Host-only test control; not copied into the service images and has no listener."""
from uuid import UUID


def alter_registered_rate(scenario):
    """Edit only one existing administrator record, through the isolated lab DB operator."""
    op = str(UUID(scenario.operation))
    query = f"""
        UPDATE operation_snapshots SET snapshot=jsonb_set(snapshot,'{{boleta,negotiatedRate}}','"6.875001"')
        WHERE operation_id='{op}' AND instruction_version=1 AND snapshot->>'state'='SETTLED'
            AND snapshot#>>'{{boleta,negotiatedRate}}'='6.500000'
        RETURNING snapshot#>>'{{boleta,negotiatedRate}}'
    """
    scenario.sql(query, 'administrator', role='administrator', reject='42501')
    assert scenario.sql(query, 'administrator') == '6.875001'
