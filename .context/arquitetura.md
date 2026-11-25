# Arquitetura e contratos

Consulte a [SPEC](../SPEC.md) para comportamentos do domínio, interfaces, persistência e políticas criptográficas. A organização dos serviços descrita na SPEC é planejada; não presuma que seus diretórios ou comandos já existam.

| Área | Fontes para a tarefa |
|---|---|
| Boleta, estados e eventos | [Schemas](../contracts/schemas/), [modelo de domínio](../contracts/domain/) e [fixtures sintéticas](../fixtures/) |
| API da plataforma e do custodiante | [Contratos OpenAPI](../contracts/openapi/) |
| Integração com o administrador | [WSDL, XSD e exemplos SOAP](../contracts/soap/) |
| Envelopes, perfis e canonicalização | [Contrato de mensagens](../contracts/messages/) e [vetores](../contracts/vectors/) |
| Fronteiras de confiança e controles | [Modelo de ameaças](../docs/security/threat-model.md) e [ADR de stack](../docs/adr/0001-stack.md) |

## Pontos de atenção

- Preserve os invariantes da SPEC: recebimento, aceitação e liquidação são distintos; falha técnica não implica rejeição financeira; reenvio não deve duplicar o efeito simulado.
- Mantenha as regras financeiras separadas da lógica de transporte, assinatura e política. TLS híbrido altera o estabelecimento de chaves, não a autenticação do canal. O perfil duplo exige ambas as assinaturas; incompatibilidades não autorizam redução automática da proteção.
- Ao editar contratos, consulte a [baseline e as regras de compatibilidade](../docs/sprint-1/README.md#congelamento-e-compatibilidade). Exemplos estruturais com assinaturas ilustrativas não substituem os [vetores assinados](../contracts/vectors/signed/).
