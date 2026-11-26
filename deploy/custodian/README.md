# Recebimento REST no custodiante — S2-07

Na raiz, com Python 3.10+, Docker Linux `amd64`, Compose com `--wait` e `cafi-transport:s2-03` do [gate TLS](../../spikes/s2-03/README.md):

```powershell
py -B deploy/custodian/lab.py
```

No Linux, use `python3` em vez de `py`. Execute com asserções habilitadas. O roteiro constrói as imagens, provisiona um cenário descartável e remove seus volumes em `finally`. O [cliente de teste](../../tests/custodian/exchanges.py) usa a identidade `platform`; o servidor escuta em `custodian.cafi.test:8443` na rede interna. Cada participante monta apenas sua identidade privada (TLS e assinatura separadas) e o registro público. Só o servidor monta a senha SCRAM de `custodian`.

| Tentativa | Resultado verificado |
|---|---|
| Consulta antes da instrução | `404 NOT_FOUND` assinado. Replay exato ainda válido conserva a ausência observada; consulta nova após a instrução obtém `200`. |
| Duas cópias idênticas e uma reemissão concorrentes | Três `202 RECEIVED`, assinados com IDs de resposta distintos e correlação da respectiva tentativa. Uma linha na inbox e um evento remoto, sequência 1. |
| Outra boleta na mesma identidade lógica | `409 IDEMPOTENCY_CONFLICT`, mensagem `BUSINESS_DIGEST_MISMATCH`. |
| Mesmo `messageId` com outros bytes | `409 IDEMPOTENCY_CONFLICT`, mensagem `MESSAGE_ID_REUSED`. Duas consultas simultâneas a UUIDs diferentes com ID comum produzem um `404` e um `409`. |
| Assinatura não corresponde aos bytes ou replay idêntico após expirar | `401`, sem recibo reutilizado. A prova de expiração aguarda a validade curta mais a tolerância C1. |
| Rota divergente; concessão retirada | `400 INVALID_SCHEMA` correlacionado ao UUID protegido; `403 FORBIDDEN` assinado para reemissão e consulta após revogação. |
| Reinício do processo; falha induzida na última gravação | Histórico preservado; `503 UNAVAILABLE` assinado e contagens inalteradas após rollback. |

O operador verifica as contagens pela base, negação de conexão cruzada e proibição de apagar a inbox. [Evidência sanitizada](../../docs/sprint-2/evidence/s2-07.json). Esse roteiro de regressão não habilita a simulação.

## Decisão e liquidação — S2-08

Com os mesmos pré-requisitos, na raiz:

```powershell
py -B deploy/custodian/verify_settlement.py
```

O verificador combina `deploy/persistence/compose.yaml`, `deploy/custodian/compose.yaml`
e `deploy/custodian/settlement.compose.yaml`, nessa ordem. Ele aplica as migrações,
provisiona a credencial do runner e inicializa uma [fixture](../../fixtures/custodian/settlement.json)
por projeto descartável, antes de iniciar o servidor REST. Não usa o worker da plataforma.
O runner não monta `/identity` nem escuta conexões. É um CLI efêmero em rede interna separada,
com login SCRAM restrito à base `custodian`. Seus comandos, via
`docker compose ... run --rm -T runner`, são:

| Comando | Efeito |
|---|---|
| `init acceptance` / `init rejection` / `init insufficient` | Inicializa caixa, posição e data. Repetir a mesma fixture não restaura saldos nem data; mudar de fixture exige um projeto novo. |
| `advance YYYY-MM-DD` | Persiste uma data igual ou posterior à atual, sem processar instruções. |
| `step` | Processa no máximo uma transição por instrução, em ordem de UUID. Repita para tornar cada estado intermediário observável. |

O calendário é **segunda a sexta, sem feriados**; não é calendário de mercado. As fixtures
partem da sexta-feira 20/11/2026; o cliente deriva D+1 como segunda-feira 23/11/2026.
Uma pendência só pode liquidar em dia útil a partir da data prevista. O cenário de sucesso
também pula para um domingo **posterior** ao vencimento e comprova que só liquida na
segunda-feira seguinte (30/11). Em modo simulado, `occurredAt` dos eventos remotos marca a
data financeira à meia-noite UTC; a sequência ordena os fatos, não o horário. A data prevista
da boleta não muda; a efetiva consta nos lançamentos e na data do evento `SETTLED`.
Os horários dos envelopes e recibos continuam independentes do relógio financeiro.

| Fixture | Resultado verificado por REST assinado e PostgreSQL |
|---|---|
| `acceptance` | `RECEIVED → ACCEPTED → PENDING_SETTLEMENT → SETTLED`. Caixa BRL 150.000,00 → 51.950,00 e posição 7 → 107. Um débito de 98.050,00 e um crédito de 100 na mesma data efetiva. |
| `rejection` | `RECEIVED → REJECTED`, com `OPERATIONAL_REJECTION` e origem `CUSTODIAN`. Caixa BRL 150.000,00 e posição 7 intactos, zero lançamentos. |
| `insufficient` | `RECEIVED → ACCEPTED → PENDING_SETTLEMENT → SETTLEMENT_FAILED`, com `INSUFFICIENT_CASH`. Caixa BRL 50.000,00 e posição 7 intactos, zero lançamentos. |

O verificador testa ainda repetição e reemissão, dois processamentos concorrentes, reinícios
do banco e do custodiante, recusa de acesso ao controle e rollback após uma restrição de teste
impedir a gravação do crédito no banco. Essa restrição só existe no cenário descartável do
verificador. Veja a [evidência sanitizada](../../docs/sprint-2/evidence/s2-08.json).
