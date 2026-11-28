# Sprint 2 — fluxo tradicional C1 em laboratório

**Referência:** commit S2-14 `db10dec4a395de2b9d82cc1b3c1ae8db8dcd5730`. O [plano](../SPRINT-2.md) é um backlog histórico, não uma prova de execução; a [matriz de partida](scope.md#matriz-de-aceite-c1) descreve o aceite. Consulte [S2-15](evidence/s2-15.json) para o resultado da repetição independente em checkout limpo: não substitua uma falha ou execução ausente por resultados históricos.

## Entregas distintas

| Etapa | Demonstrado / pendente |
|---|---|
| [Sprint 1](../sprint-1/README.md) | Contratos congelados, vetores e provas **isoladas** de assinatura, canonicalização e TLS; não executou os serviços financeiros. |
| Sprint 2, C1 | API da gestora, plataforma com PostgreSQL, custodiante REST, administrador SOAP 1.2, outbox/inbox, recuperação e conciliação em laboratório com dados sintéticos. A [execução S2-14](evidence/s2-14.json) registrou saída 0 e sete suítes sem skips, porém sobre árvore suja antes do commit. A repetição limpa S2-15 é a referência para encerrar o aceite. |
| MVP | **Pendente:** C2–C6 em ambos os adaptadores, ML-DSA/assinatura dupla operacionais, TLS híbrido no negócio, controle de políticas, migração e rotação sob carga (T06/T10/T11), T05/T14 integrais, piloto/benchmarks e avaliação completa T01–T14. A prova isolada de grupo híbrido não constitui fluxo híbrido. |

## Reprodução

Em checkout **confiável e limpo** da revisão acima, com Git, Python ≥ 3.10 (`py` no Windows), PowerShell, Docker Engine em modo Linux `amd64`, Compose compatível e a imagem `cafi-transport:s2-03` preparada conforme [instruções da stack](../../spikes/s2-03/README.md):

```powershell
py -B scripts/verify-sprint2/verify.py
```

O [manual do verificador](../../scripts/verify-sprint2/README.md) descreve versões, montagem das imagens, timeouts, relatório JSON sanitizado **fora** do checkout e opção `--demo-only` (não é aceite). Não use `PYTHONOPTIMIZE`; não execute simultaneamente outro verificador Compose (as tags locais de imagens são compartilhadas). O script prepara identidades efêmeras, projetos e volumes separados por cenário; exerce REST/JSON, SOAP/XML, PostgreSQL e mTLS reais. A demonstração cria operação por REST, acompanha envio e liquidação simulada, registra/consulta SOAP e lê `SETTLED`/`MATCHED` pela API, sem editar manualmente o banco. O relógio financeiro só considera segunda a sexta, sem feriados; não há transação financeira real. Exigir saída **0**, sete suítes completas e **zero skips**; falha/timeout/skip ou mecanismo diferente de C1 bloqueia o aceite. A opção `--inject-failure` deve retornar 1, mas não substitui a execução integrada.

## Índice de evidências sanitizadas

| Recorte | Evidência versionável e limite |
|---|---|
| S2-01, escopo e contratos | [Baseline/matriz](scope.md); especifica critérios, não execução. |
| S2-02, parsers e assinaturas | [Prova inicial](evidence/s2-02.json) e [regressão na imagem de transporte](evidence/s2-03-body.json): JCS/C14N e ECDSA, ML-DSA, dupla; não são perfis de negócio C2–C6. |
| S2-03, gate da stack | [Trocas REST/SOAP nos três enlaces](evidence/s2-03.json), X25519 e X25519MLKEM768 nas duas pontas em provas separadas; não são operação financeira híbrida. |
| S2-04, persistência | [PostgreSQL, três bases e logins](evidence/s2-04.json); infraestrutura, sem fluxo. |
| S2-05, fronteira C1 | [Envelopes, autenticação, autorização e parsers](evidence/s2-05.json); adaptadores, ainda sem transação financeira. |
| S2-06, API da gestora | [Criação, consulta, replay e rejeição local](evidence/s2-06.json); sem worker remoto. |
| S2-07–08, custodiante | [Recebimento idempotente](evidence/s2-07.json) e [liquidação atômica/rejeição/saldo insuficiente](evidence/s2-08.json); antes da integração da plataforma. |
| S2-09–10, plataforma REST | [Envio e projeção](evidence/s2-09.json), [recuperação, reinício e lacunas](evidence/s2-10.json); sem SOAP/conciliação nessas rodadas. |
| S2-11–12, SOAP | [Serviço, Faults e limites](evidence/s2-11.json), [publicação, consulta, retomada](evidence/s2-12.json); S2-12 não comparou três registros. |
| S2-13, conciliação | [MATCHED, NOT_READY, DIVERGENT](evidence/s2-13.json); escopo C1. |
| S2-14, integração | [Sete suítes, três enlaces na mesma operação, cenários e contraprova](evidence/s2-14.json); **árvore suja** antes do commit S2-14. |
| S2-15, repetição limpa | [Resultado, revisão, estado antes/depois, exits e limites](evidence/s2-15.json); usar esta rodada para o fechamento documental. |

### Matriz de encerramento → testemunho

Cada linha é um **recorte C1** dos IDs da [SPEC §8](../../SPEC.md#8-verificação-e-critérios-de-entrega), não a aprovação integral de T01–T14. Os testemunhos por suíte, operação e cenário estão em [S2-15](evidence/s2-15.json), com detalhamento histórico em [S2-14](evidence/s2-14.json).

| Critério do [plano](../SPRINT-2.md#critérios-de-encerramento-da-sprint) | Evidência rastreável |
|---|---|
| Stack, proteção e três enlaces C1 | S2-02/03/05 e S2-15 `reconciliation`/`tlsLinks`, mais `parser-and-identity`: na **mesma operação**, REST gestora→plataforma, REST plataforma→custodiante, SOAP plataforma→administrador; TLS 1.3, X25519, `TLS_AES_256_GCM_SHA384`, SAN/cadeia/mTLS e assinatura ECDSA, política 1. |
| T01, registro→liquidação→SOAP→conciliação | S2-15 `platform`, `settlement`, `custody`, `administrator`, `reconciliation`: `SETTLED`/`MATCHED`, um débito e um crédito; rejeição local/operacional e saldo insuficiente sem lançamento parcial. |
| T02/T09, concorrência e conflito | S2-15 `platform`, `custody`, `administrator`: replay, reemissão, colisão de ID e digest de negócio distintos sem novo efeito. |
| T03/T04/T13, falha e retomada | S2-15 `recovery`, `administrator`, `reconciliation`: consulta antes de reenvio, resposta perdida, reinício, indisponibilidade, `UNKNOWN`/`BLOCKED`/`NOT_READY` e liquidação preservada. |
| T05/T07/T08, negativos C1 | S2-15 `parser-and-identity` e suítes dos serviços: assinatura, escopo/identidade, JSON/XML inválidos e recusa TLS sem fallback; não cobre todos os perfis. |
| T12, histórico e divergência | S2-15 `custody`, `recovery`, `reconciliation`: lacuna/regressão sem avanço indevido e divergência por campo com `SETTLED` preservado. |
| Reprodução e falha obrigatória | S2-15 registra checkout detached limpo, comando e exits; S2-14 registra contraprova `--inject-failure` com saída 1, **não repetida automaticamente** pela rodada S2-15. |

Somente resumos e IDs sintéticos são versionados. Relatórios detalhados ficam fora do repositório; não versionar stdout bruto, chaves privadas, certificados de laboratório, credenciais, volumes ou logs não sanitizados. CI em runner fixado **não foi executada/configurada**; não interpretar a reprodução local como CI ou como benchmark. A baseline da Sprint 1 permanece congelada; mudanças incompatíveis nos contratos exigem versão, migração, novos vetores e nova verificação conforme a [SPEC §4](../../SPEC.md#4-contratos-de-integração).
