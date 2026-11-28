# Verificação S2-14 (C1)

Na raiz ou em qualquer diretório, com Python ≥ 3.10, Git, Docker Engine Linux
`amd64`, Compose com `--wait`/`!override` e a imagem base
`cafi-transport:s2-03` preparada conforme
[`spikes/s2-03/README.md`](../../spikes/s2-03/README.md):

```powershell
py -B scripts/verify-sprint2/verify.py
```

No Linux, use `python3 -B`. No Windows, o verificador procura Docker Desktop
também em `%LOCALAPPDATA%\Programs\DockerDesktop\resources\bin`. **Não execute
ao mesmo tempo que outros verificadores Compose**: os nomes de projeto e volumes
são exclusivos, mas as imagens locais `:s2-*` são compartilhadas. Não use
`PYTHONOPTIMIZE`; as provas existentes dependem de `assert`.

O comando constrói as imagens, inicializa bases e identidades efêmeras, roda os
cenários de plataforma, liquidação, worker REST, recuperação, worker SOAP,
conciliação e negativos da fronteira C1. `links.py` executa a suíte real de
`deploy/platform/verify_reconciliation.py` e, antes da limpeza do cenário
`missing`, confere e emite apenas metadados sanitizados da observação TLS da
gestora, dos dois workers e dos três listeners, na **mesma operação**.
O sucesso de `incomplete_then_equal` é a demonstração da gestora:
`POST` REST assinado, entrega REST real, relógio financeiro isolado, registro e
consulta SOAP real, estado `SETTLED` e resultado `MATCHED` via API REST.
`divergent` confirma `DIVERGENT` pela API e diferença persistida sem alterar
lançamentos. Cada verificador de serviço cria e remove seu próprio projeto
Compose e os volumes em `finally`. Não há mock no cenário de sucesso; os
verificadores defensivos injetam falhas somente no laboratório isolado.

Para **somente** a demonstração ponta a ponta (não é aceite da sprint):

```powershell
py -B scripts/verify-sprint2/verify.py --demo-only
```

Para comprovar que uma falha obrigatória não pode terminar com zero, sem iniciar
Docker:

```powershell
py -B scripts/verify-sprint2/verify.py --inject-failure
# saída esperada: 1, relatório FAILED
```

O relatório JSON sanitizado é gravado fora do checkout no diretório temporário
do usuário (ou `--report CAMINHO` fora do checkout). Inclui revisão Git, hash
SHA-256 do `git status` (sem paths), hashes SHA-256 dos scripts executados,
versões observadas, parâmetros, exit de cada
suíte e testemunhos por cenário com campos permitidos. **Não** armazena stdout
bruto, dumps SQL, logs de serviços, certificados nem segredos. Logs estruturados
dos serviços são conferidos pelos respectivos verificadores; inspecione seus
controles TLS de ambas as pontas e as ressalvas em
[`deploy/platform/README.md`](../../deploy/platform/README.md). Uma falha, timeout
(exit 124), ausência de testemunho, skip ou mecanismo TLS divergente bloqueia
o aceite; em falha o relatório contém apenas diagnóstico sanitizado. Limite por
suíte: 1800 s; parser/identidade: 300 s; Compose interno usa prazos próprios
(por exemplo 30 s de readiness, 3 s de conexão e 10 s de troca).
Em recuperação, `wire` e `ledger` são reduzidos a ação, IDs de
correlação/requisição/resposta, resultado, modo, mecanismo e ordem de tentativa;
nenhum payload é incluído.
As versões de Python/OpenSSL/h11/lxml/rfc8785 são lidas da própria imagem-base
fixada, sem tratá-las como prova de suporte TLS no fluxo.
Em recuperação, `disallowed` deve emitir cinco testemunhos distintos e
`migration` três operações distintas; não são cinco/três aprovações
substituíveis por uma única linha `PASS`.

| Linha obrigatória | Execução atual exigida |
|---|---|
| T01, sucesso `SETTLED`/`MATCHED`, rejeição local/operacional/saldo | `platform`, `settlement`, `custody`, `administrator`, `reconciliation` |
| T02/T09, concorrência, replay, conflito | `platform`, `custody`, `administrator` |
| T03/T04/T13, timeout, restart, indisponibilidade | `recovery`, `administrator`, `reconciliation` |
| T12, lacuna, regressão, divergência | `custody`, `recovery`, `reconciliation` |
| T05/T07/T08 (recorte C1), parser, identidade, mTLS | `parser-and-identity` e cenários dos serviços |

Os verificadores de S2-09/10/12/13 instrumentam C1 real: TLS 1.3, X25519,
`TLS_AES_256_GCM_SHA384`, mTLS e ECDSA P-256. O relatório exige três
observações independentes de conexão cliente (versão, grupo, suíte, SAN e
`verifyCode=0`, cadeia, certificado EC P-256, ausência de retomada/0-RTT)
e logs de servidor correlacionados ao mesmo UUID. A suíte de fronteira verifica
negativos adicionais, mas **não substitui** os três enlaces reais. Exigir ambos
os tipos de prova impede considerar o gate S2-02/03 como execução do fluxo.
Não há alegação de C2–C6, migração de política ou MVP completo. No runner
compartilhado sem Docker Linux/Compose e imagem-base fixada, CI é bloqueada:
não cadastrar job que passe com skip nem usar serviço simulado como substituto.
O [resumo sanitizado desta execução](../../docs/sprint-2/evidence/s2-14.json)
identifica a revisão, a árvore suja, os exits, as falhas anteriores e os
limites; a revisão independente em checkout limpo continua pendente.
