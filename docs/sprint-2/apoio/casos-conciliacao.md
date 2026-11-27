# S2-13 · Casos de mesa para conciliação

Estes casos de mesa usam dados sintéticos e descrevem resultados esperados, sem execução dos serviços. Registros concordantes geram `MATCHED`, uma diferença em um campo gera `DIVERGENT` e um registro ausente gera `NOT_READY`. [SPEC, seção 6](../../../SPEC.md#6-simulação-e-conciliação)

O arquivo `docs/SPRINT-2.md` não está nas branches disponíveis do repositório. Os resultados abaixo seguem a SPEC e os contratos. O aceite específico da S2-13 no plano da sprint permanece sem conferência.

## Chave e campos comparados

A chave é o par `(operationId, instructionVersion)`. Nos snapshots REST da plataforma e do custodiante, os campos ficam em `protected.operationId` e `protected.instructionVersion`. No SOAP, ficam em `SignedContent/Protected/OperationId` e `SignedContent/Protected/InstructionVersion`.

| Campo da SPEC | Plataforma e custodiante REST | Administrador SOAP, dentro de `SignedContent` |
|---|---|---|
| Carteira | `payload.boleta.portfolioId` | `Payload/Boleta/PortfolioId` |
| Ativo | `payload.boleta.assetId` | `Payload/Boleta/AssetId` |
| Quantidade | `payload.boleta.quantity` | `Payload/Boleta/Quantity` |
| Taxa negociada | `payload.boleta.negotiatedRate` | `Payload/Boleta/NegotiatedRate` |
| Preço unitário (PU) | `payload.boleta.unitPrice` | `Payload/Boleta/UnitPrice` |
| Valor financeiro | `payload.boleta.grossAmount` | `Payload/Boleta/GrossAmount` |
| Moeda | `payload.boleta.currency` | `Payload/Boleta/Currency` |
| Data prevista de liquidação | `payload.boleta.settlementDate` | `Payload/Boleta/SettlementDate` |
| Resultado da liquidação | `payload.state` | `Payload/State` |

Os valores de quantidade, taxa, PU e financeiro são representados por strings nos contratos e comparados como valores exatos, sem ponto flutuante. A data prevista da boleta é distinta da data efetiva da liquidação. Os snapshots consultados não definem um campo separado para a data efetiva.

Os caminhos correspondem às consultas de status da [plataforma REST](../../../contracts/openapi/platform.yaml) e do [custodiante REST](../../../contracts/openapi/custodian.yaml), que referenciam o [schema de mensagens](../../../contracts/messages/envelope.schema.json) e o [schema da boleta](../../../contracts/schemas/boleta.schema.json), e à operação `GetOperation` do [administrador SOAP](../../../contracts/soap/administrator.wsdl), conforme o [XSD do administrador](../../../contracts/soap/administrator.xsd) e o [XSD do conteúdo assinado](../../../contracts/schemas/xml/signed-content.xsd).

## Caso 1 · Registros concordantes

| Dado | Plataforma | Custodiante REST | Administrador SOAP |
|---|---|---|---|
| ID da operação | `11111111-1111-4111-8111-111111111111` | `11111111-1111-4111-8111-111111111111` | `11111111-1111-4111-8111-111111111111` |
| Versão da instrução | `1` | `1` | `1` |
| Carteira | `FUNDO-ALFA` | `FUNDO-ALFA` | `FUNDO-ALFA` |
| Ativo | `DEB-FICTICIA-01` | `DEB-FICTICIA-01` | `DEB-FICTICIA-01` |
| Quantidade | `100` | `100` | `100` |
| Taxa negociada | `6.500000` | `6.500000` | `6.500000` |
| PU | `980.500000` | `980.500000` | `980.500000` |
| Valor financeiro | `98050.00` | `98050.00` | `98050.00` |
| Moeda | `BRL` | `BRL` | `BRL` |
| Data prevista de liquidação | `2026-11-20` | `2026-11-20` | `2026-11-20` |
| Resultado da liquidação | `SETTLED` | `SETTLED` | `SETTLED` |

**Resultado esperado.** A plataforma informa `reconciliationStatus = MATCHED`, pois os três snapshots têm a mesma chave e concordam nos nove campos.

## Caso 2 · Divergência em um único campo

O caso 1 é repetido com uma única mudança no registro do administrador. O valor de `Payload/Boleta/NegotiatedRate` passa de `6.500000` para `6.600000`. O cálculo do financeiro usa a quantidade e o PU, que permanecem iguais.

| Dado | Plataforma | Custodiante REST | Administrador SOAP |
|---|---|---|---|
| ID da operação | `11111111-1111-4111-8111-111111111111` | `11111111-1111-4111-8111-111111111111` | `11111111-1111-4111-8111-111111111111` |
| Versão da instrução | `1` | `1` | `1` |
| Carteira | `FUNDO-ALFA` | `FUNDO-ALFA` | `FUNDO-ALFA` |
| Ativo | `DEB-FICTICIA-01` | `DEB-FICTICIA-01` | `DEB-FICTICIA-01` |
| Quantidade | `100` | `100` | `100` |
| Taxa negociada | `6.500000` | `6.500000` | **`6.600000`** |
| PU | `980.500000` | `980.500000` | `980.500000` |
| Valor financeiro | `98050.00` | `98050.00` | `98050.00` |
| Moeda | `BRL` | `BRL` | `BRL` |
| Data prevista de liquidação | `2026-11-20` | `2026-11-20` | `2026-11-20` |
| Resultado da liquidação | `SETTLED` | `SETTLED` | `SETTLED` |

**Resultado esperado.** A plataforma informa `reconciliationStatus = DIVERGENT` e registra a divergência em `negotiatedRate` com os valores das três origens. A liquidação fica em `SETTLED`, estado terminal produzido pelo custodiante antes da conciliação. O débito de caixa e o crédito de ativos já foram gravados na liquidação simulada. A conferência posterior altera apenas o resultado da conciliação e registra a diferença para análise.

## Caso 3 · Registro ausente no administrador

A plataforma e o custodiante têm os snapshots do caso 1. A consulta SOAP `GetOperation` da mesma chave retorna um Fault autenticado. A tabela mostra a chave do erro e a ausência do snapshot na última coluna. [Contrato SOAP para ausência](../../../contracts/soap/README.md#mapeamento)

| Dado | Plataforma | Custodiante REST | Administrador SOAP |
|---|---|---|---|
| ID da operação | `11111111-1111-4111-8111-111111111111` | `11111111-1111-4111-8111-111111111111` | `11111111-1111-4111-8111-111111111111` no erro |
| Versão da instrução | `1` | `1` | `1` no erro |
| Carteira | `FUNDO-ALFA` | `FUNDO-ALFA` | Sem snapshot |
| Ativo | `DEB-FICTICIA-01` | `DEB-FICTICIA-01` | Sem snapshot |
| Quantidade | `100` | `100` | Sem snapshot |
| Taxa negociada | `6.500000` | `6.500000` | Sem snapshot |
| PU | `980.500000` | `980.500000` | Sem snapshot |
| Valor financeiro | `98050.00` | `98050.00` | Sem snapshot |
| Moeda | `BRL` | `BRL` | Sem snapshot |
| Data prevista de liquidação | `2026-11-20` | `2026-11-20` | Sem snapshot |
| Resultado da liquidação | `SETTLED` | `SETTLED` | Sem snapshot |

O erro correlacionado tem `Protected/MessageType = ERROR` e `Payload/Code = NOT_FOUND` dentro de `Fault/Detail/Message/SignedContent`. [Exemplo de Fault no contrato SOAP](../../../contracts/soap/examples/fault.xml)

**Resultado esperado.** A plataforma informa `reconciliationStatus = NOT_READY` porque falta o registro do administrador. O estado financeiro da plataforma e do custodiante permanece `SETTLED`.
