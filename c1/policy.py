"""Local C1 v1 laboratory policy, matching the synthetic participant catalog."""
from .security import Direction

PARTICIPANTS = {
    'manager': 'GESTORA-ALFA', 'platform': 'PLATFORM',
    'custodian': 'CUSTODIANTE-GAMA', 'administrator': 'ADMINISTRADOR-DELTA',
}
LINKS = {
    'platform': ('manager', 'CREATE_OPERATION', 'QUERY_OPERATION'),
    'custodian': ('platform', 'SUBMIT_INSTRUCTION', 'QUERY_INSTRUCTION'),
    'administrator': ('platform', 'REGISTER_OPERATION', 'QUERY_ADMIN_RECORD'),
}


def direction(integration, *, response, signing_key_id, trusted_key_ids):
    client, command, query = LINKS[integration]
    sender, recipient = (integration, client) if response else (client, integration)
    return Direction(PARTICIPANTS[sender], PARTICIPANTS[recipient], sender + '.cafi.test',
                     recipient + '.cafi.test', 'LAB', frozenset(trusted_key_ids), signing_key_id,
                     frozenset((command, query)), frozenset([('GESTORA-ALFA', 'FUNDO-ALFA')]))
