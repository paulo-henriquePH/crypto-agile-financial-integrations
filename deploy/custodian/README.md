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

O operador verifica as contagens pela base, negação de conexão cruzada e proibição de apagar a inbox. [Evidência sanitizada](../../docs/sprint-2/evidence/s2-07.json). Este cenário exercita o cliente de plataforma diretamente; o envio da outbox, a decisão e a liquidação pertencem a outras tarefas.
