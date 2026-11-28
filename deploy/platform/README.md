# Plataforma da gestora — S2-06

Na raiz, com Python ≥ 3.10, Docker Linux `amd64`, Compose com `--wait` e a imagem local `cafi-transport:s2-03` preparada pelo [gate de transporte](../../spikes/s2-03/README.md):

```powershell
py -B deploy/platform/lab.py verify
```

Em Linux use `python3 -B` em lugar de `py -B`. O comando constrói a imagem da plataforma, cria projeto/volumes exclusivos, aplica as migrações S2-04 e a migração privativa da plataforma, emite identidades, inicia o listener e executa [requisições reais](../../tests/platform/exchanges.py) e [asserções do operador](verify.py). O `finally` remove inclusive volumes do perfil `tools`. Uma falha de build, verificação ou limpeza resulta em saída não zero. Execute sem otimização de asserts (`-O`/`PYTHONOPTIMIZE`).

### Sessão interativa

```powershell
py -B deploy/platform/lab.py up demo06
$dc = @('compose','-p','cafi-s2-demo06','-f','deploy/persistence/compose.yaml','-f','deploy/platform/compose.yaml')
docker @dc run --rm -T manager python -m services.platform.client create EXEMPLO-1
# Consulte com o operationId da linha JSON recebida; repita create para observar 200.
docker @dc run --rm -T manager python -m services.platform.client query <UUID>
"SELECT count(*) FROM outbox" | py -B deploy/persistence/lab.py sql demo06 platform
py -B deploy/platform/lab.py down demo06
```

Substitua `<UUID>` pelo identificador antes de executar. `down` apaga o cenário nomeado. A plataforma escuta em `platform.cafi.test:8443` na rede interna, sem porta publicada. O cliente usa um POST por conexão, verifica o servidor por SAN e valida assinatura, correlação, corpo e `Location`. O gerador offline emite certificados de um dia e pares TLS/mensagem distintos, copia **somente** a identidade própria e o registro público para cada volume e descarta a chave da CA. Após expiração, recrie o cenário. A plataforma roda como UID 999 com volumes somente leitura: sua identidade e a senha SCRAM do login `platform`. A gestora não monta senhas do banco nem as privadas da plataforma.

### O que observar

| Estímulo | HTTP e efeito esperado |
|---|---|
| Duas conexões criam a mesma ordem | Um `201`, um `200`, mesmo `operationId` (UUID aleatório) e `instructionVersion=1`; dois eventos contíguos e uma intenção. |
| Mesmo envelope ou nova emissão da mesma ordem | `200`, nova resposta correlacionada, `Location` e decisão original. Alteração de negócio na identidade ou bytes diferentes no mesmo ID: `409 IDEMPOTENCY_CONFLICT`. |
| Mesmo `messageId` simultâneo para ordens diferentes | Um `201`, um `409` e um único efeito. |
| Erro de cadastro, data ou financeiro | `201 REJECTED`, com UUID, origem `LOCAL`, motivo também no evento e sem outbox. O produto usa decimal exato, `HALF_UP`, escala 2 e limite de 18 dígitos inteiros. Datas úteis de segunda a sexta, sem feriados. |
| Quantidade fora do schema; validade expirada | `400 INVALID_SCHEMA` assinado quando há contexto recuperável; `401` sem resultado para envelope fora da validade. |
| Consulta por UUID | `200` com histórico ordenado e entrega/conciliação independentes; `404 NOT_FOUND` assinado para ausência; `403 FORBIDDEN` sem dados para outro titular ou carteira sem permissão. |
| UUID da rota difere do UUID assinado | `400 INVALID_SCHEMA` assinado, com `operationId` protegido e `requestMessageId` da tentativa. O teste troca um UUID existente por um ausente e vice-versa enquanto o papel `platform` está sem `SELECT` em `operations`; não há leitura de titularidade nem novo recibo. |
| Falha na última inserção (recibo) | `503 UNAVAILABLE` assinado; rollback de operação, eventos e outbox. |

O papel de execução da S2-06 tinha `INSERT,SELECT`, sem `UPDATE`/`DELETE` nas quatro tabelas. A S2-09 acrescenta apenas atualizações de entrega, data de atualização e metadados de envio/consulta; boleta, eventos e fatos continuam sem `UPDATE`/`DELETE`. A transação de entrada segura travas transacionais PostgreSQL em namespaces distintos: ordem da gestora, depois ID de mensagem. Elas serializam inclusive chaves ainda inexistentes; colisão do hash da trava apenas serializa trabalho adicional. As identidades completas continuam protegidas por unicidade. O recibo guarda SHA-256 dos **bytes recebidos** e o resultado lógico; a identidade da ordem compara SHA-256 de JCS da boleta. O estado atual vem do último evento, e a sequência ordena a projeção. A criação lê sempre o evento 2. A intenção inicial contém destinatário, payload e versão; envelope ainda não preparado, zero tentativas.

Para provar atualidade sem implementar o remetente futuro, **só o verificador** acrescenta um terceiro evento sintético, reinicia o serviço e compara a consulta nova com o replay da criação. Também insere uma operação de outro titular e remove a concessão no catálogo para testar sigilo. Essas intervenções não são funcionalidades do endpoint. [Resultado da execução](../../docs/sprint-2/evidence/s2-06.json).

Para repetir a regressão de inicialização dos parsers, execute `powershell -NoProfile -File scripts/verify-c1/verify.ps1`. Um processo Python novo sincroniza oito threads na primeira leitura JSON, na primeira leitura SOAP e em uma rodada mista. O teste confere que JSON não compila XSD e que o XSD é compilado uma única vez. No `lab.py verify`, os clientes também sincronizam a primeira assinatura e o envio em conexões mTLS distintas para o serviço recém-iniciado.

## Envio e acompanhamento REST — S2-09

Com os mesmos pré-requisitos e Compose com suporte a `!override`, execute na raiz:

```powershell
py -B deploy/platform/verify_custody.py
```

O roteiro constrói as imagens `cafi-platform:s2-09` e `cafi-custodian:s2-09`, aplica as migrações,
provisiona os enlaces `gestora → plataforma` e `plataforma → custodiante` com volumes independentes,
e executa cinco cenários isolados. Cada boleta é registrada pela API REST da gestora, sem inserção
direta no banco; as consultas da gestora também passam pela API C1. O runner privado da S2-08
controla o calendário financeiro (sexta `2026-11-20` e D+1 útil `2026-11-23`, sem feriados).
O roteiro remove seus projetos e volumes e não usa certificados ou dados reais.

| Cenário | O que o roteiro verifica |
|---|---|
| Liquidação | Uma tentativa persistida, mesmo com dois workers concorrentes; falha ao gravar `SENT` não envia. `202` avança somente a `RECEIVED`; novas consultas obtêm `ACCEPTED`, `PENDING_SETTLEMENT` e `SETTLED`. Um débito e um crédito remotos. Repetir um snapshot idêntico em nova consulta não muda os eventos nem o timestamp da projeção. O `202` e cinco `200` têm recibos cujo SHA-256 corresponde aos bytes enviados pelo custodiante; o timestamp e o resultado do recibo não duplicam o payload. Uma consulta da gestora tentando reutilizar o ID de resposta recebe `409`. |
| Rejeição operacional | O worker contínuo consulta e projeta `REJECTED` com `OPERATIONAL_REJECTION` e origem `CUSTODIAN`, sem lançamentos. |
| Fronteira defensiva | Um par C1 exclusivo do verificador assina respostas com correlação errada, prefixo regressivo ou modificado, lacuna, salto, boleta divergente ou reutilização de um ID de resposta já gravado. Uma restrição isolada falha na segunda gravação de um sufixo válido. Histórico, fatos e recibos não mudam nesses casos. |
| Rollback após `202` | Uma restrição do teste bloqueia o evento `RECEIVED` depois do registro do recibo na transação. O custodiante permanece em `RECEIVED`, mas a plataforma continua em `SENT`, sem novo recibo, confirmação de entrega ou consulta agendada. |
| Colisão concorrente | O verificador faz o custodiante assinar dois `202` com o mesmo ID para operações distintas. Duas tentativas se cruzam em mTLS; um recibo é confirmado e somente a operação correspondente avança. |

O [overlay do worker](custody.compose.yaml) vem após os overlays de plataforma, custodiante e liquidação
na ordem usada pelo verificador. O serviço `worker` executa continuamente por padrão; `run --rm -T worker --once`
executa apenas uma rodada e falha se algum item da rodada falhar. O intervalo inicial das consultas é
1 s; os limites de conexão e de troca são 3 s e 10 s, configuráveis por
`--poll-interval`, `--connect-timeout` e `--exchange-timeout`. Cada consulta cria novo `messageId`.
Na S2-09, uma falha não gerava rejeição financeira, não rearmava o acompanhamento e não provocava retransmissão. A regressão deste comando na árvore S2-10 verifica que a recuperação não altera os efeitos financeiros da S2-09.
Respostas autenticadas e correlacionadas usam a mesma reserva transacional de IDs da API da gestora.
O worker guarda o digest SHA-256 dos bytes recebidos, não reserializados, e apenas os metadados
necessários para identificar o resultado. O [registro de recibos](../../services/platform/response_receipts.py)
usa a transação do chamador e não decide a ação de negócio. O custodiante do verificador observa o
digest dos bytes enviados sem salvar o envelope nos logs.
[Evidência sanitizada](../../docs/sprint-2/evidence/s2-09.json).

## Recuperação REST — S2-10

Com os mesmos pré-requisitos, na raiz:

```powershell
py -B deploy/platform/verify_recovery.py
```

O verificador cria projetos e volumes exclusivos, prepara as bases e identidades C1, usa a API REST da gestora, o worker real e o próprio custodiante com uma camada de injeção **após** a transação. O [overlay normal](custody.compose.yaml) usa as imagens `cafi-platform:s2-10` e `cafi-custodian:s2-10`; não ativa a camada de teste nem oferece rota de falha. O operador do teste controla o arquivo temporário no contêiner de teste, encerra o worker com `SIGKILL` e usa o CLI isolado de liquidação S2-08; não escreve o estado financeiro pelo banco. O runner aceita nomes de cenários individuais para investigação (`--help`); sem nomes, executa todos e limpa os recursos que criou. Use os asserts ativados.

| Cenário | Observação esperada |
|---|---|
| `outbox` | Reiniciar PostgreSQL antes do primeiro envio; recuperar a intenção registrada pela gestora. |
| `lost_reply`, `killed` | Perder o `202` após commit ou matar o worker antes da confirmação. Primeiro recuperar por consulta, sem novo envio. Timeout de consulta mantém `UNKNOWN`; histórico completo pode recuperar até `SETTLED` com um débito e um crédito. |
| `expired` | Matar o worker após preparar `SENT` e antes de abrir socket. Prova de ausência vencida não autoriza envio; nova ausência fica persistida através de reinício do banco. Emitir novo ID, validade e assinatura com a mesma identidade de negócio; conservar bytes anteriores. |
| `gap_closed`, `gap_open` | Resposta assinada omite um evento; sem mutação parcial. Após reinício, histórico contíguo que cubra a sequência pendente restaura a projeção; um prefixo menor não encerra a recuperação. Se a lacuna persiste, a quinta falha bloqueia sem alterar os fatos. |
| `unavailable`, `disallowed` | Validar atraso, limite e persistência de `BLOCKED`; sem resend diante de `404` sem assinatura válida ou sem correlação, nem retry de esquema/autorização. |
| `known_receipt` | `404` válido, mas contraditório após um recebimento confirmado, não habilita retransmissão. |
| `migration` | Exporta a revisão `a22db16` via Git em diretório temporário e usa seu worker e suas migrações reais. Após a 004, `403/FORBIDDEN` permanece bloqueado e sem tráfego; timeout sem recibo e `503` correlacionado continuam recuperáveis por consulta. |
| `write_expiry` | Pausa na entrada de `Channel.send`, após mTLS, até 75 ms após a validade do `404`. Confere zero chamadas a `SSL_write_ex` e zero inbox antes de obter nova prova; a consulta nova permite recuperar o envio. |

O worker usa `--poll-interval 1`, `--connect-timeout 3` e `--exchange-timeout 10` por padrão; o teste de timeout usa 2 s para a troca. `--retry-base` define o primeiro atraso (padrão 1 s, duplicado a cada falha) e `--retry-jitter` aplica variação proporcional simétrica (padrão 0; valor em `[0, 1)`). Cada invocação `--once` abre um processo novo; falha observada na rodada retorna 1, ausência de trabalho retorna 0. `outbox.attempts` conta preparações de envio confirmadas no banco, mesmo se o socket nunca chegou a abrir; `custody_attempts` registra também consultas, desfecho, código e atraso. A quinta falha grava o atraso de referência de 16 s, mas bloqueia imediatamente. A retomada administrativa de `BLOCKED` não é implementada neste recorte.

Veja a [evidência sanitizada](../../docs/sprint-2/evidence/s2-10.json). O recorte não inclui SOAP, conciliação, troca de políticas nem aceite integrado da Sprint 2.

## Atualização e leitura SOAP — S2-12

Com os pré-requisitos acima, na raiz:

```powershell
$env:PATH = "$env:LOCALAPPDATA\Programs\DockerDesktop\resources\bin;$env:PATH" # só se necessário
py -B deploy/platform/verify_administrator.py
```

No Linux, use `python3 -B`. O comando constrói as três imagens S2-12 e usa projetos, volumes, identidades efêmeras e bases isoladas. Execute com asserts habilitados e em série com outros verificadores Compose. Sem argumentos, executa toda a suíte; `--help` lista cenários para repetir individualmente. O runner limpa seus projetos em `finally`. As injeções de teste modificam somente a emissão após a transação do serviço real, ou atuam via Compose/SQL do operador; não estão habilitadas no overlay normal.

| Cenário | Prova |
|---|---|
| `rollback_outage` | Uma restrição PostgreSQL rejeita só a nova intenção. Terminal local, fatos e recibo REST fazem rollback; o terminal remoto fica intacto. A intenção é persistida na rodada seguinte mesmo com o administrador parado. Recuperação por ausência assinada, uso único da prova e registro idempotente. |
| `lost_reply` | Recuperação REST até o terminal enfileira a intenção. Perda da resposta SOAP depois do commit, `SIGKILL` do worker e timeout na consulta não duplicam o registro. Uma consulta posterior confirma; duas leituras independentes usam IDs novos. |
| `rejection`, `insufficient` | Rejeição local não cria intenção; snapshots terminais do custodiante conservam motivo/origem quando aplicáveis, sem lançamento parcial. |
| `defensive` | Assinatura, correlação, versão, negócio e Faults são rejeitados quando incompatíveis. `Reason=NOT_FOUND` externo não autoriza reenvio diante de `FORBIDDEN` assinado. |
| `exhausted` | Falhas do banco no administrador geram Fault `UNAVAILABLE` assinado. A quinta falha bloqueia sem sexta tentativa, sem perder a intenção nem desfazer a liquidação. |
| `legacy` | Worker e migrações da base S2-11 reais (via `git archive`). A 005 não retropreenche o terminal e `GetOperation` devolve o registro independente já existente, inclusive com taxa diferente. |

O overlay normal segue a ordem `deploy/persistence/compose.yaml`, `deploy/platform/compose.yaml`, `deploy/custodian/compose.yaml`, `deploy/custodian/settlement.compose.yaml`, `deploy/platform/custody.compose.yaml`, `deploy/administrator/compose.yaml`, `deploy/platform/administrator.compose.yaml`. Depois de aplicar as migrações, provisionar as identidades com `manager-identity-init`, `identity` (custódia) e `administrator-identity-init` (SOAP). O verificador mostra os comandos de inicialização, incluindo a fixture/runner financeiro S2-08. Iniciar `platform`, `custodian`, `administrator`, `worker` (REST) e `administrator-worker` (SOAP); `run --rm -T administrator-worker --once` processa uma rodada, com saída 1 se observar alguma falha. Cada worker monta somente a identidade de seu enlace; as chaves TLS e ECDSA de mensagem continuam distintas.

Para investigar, consulte `outbox` por `message_type='REGISTER_OPERATION'` e `administrator_attempts`. O estado `administrator_status` é separado de `operations.delivery_status`. `outbox.attempts` conta envelopes preparados e gravados, mesmo que ainda não escritos; o diário registra também indisponibilidade pré-envio e consultas. Parâmetros padrão: conexão 3 s, troca 10 s, backoff 1/2/4/8/16 s e jitter 0. Não há retomada administrativa de `BLOCKED` neste recorte. A primeira instalação usa a migração 005; ao atualizar, aplique-a antes de subir o worker REST novo. Uma operação já terminal na S2-11 fica fora da publicação automática, sem alterar estado/histórico.

`services.platform.administrator.get_operation(db, client, operation)` é uma leitura interna para uso futuro: passa pelo mTLS e ECDSA do administrador, usa a carteira vinculada à operação e retorna o resultado ou Fault verificado da consulta nova. Não devolve o ACK anterior como consulta. Registra metadados do recibo, não snapshots de conciliação. O teste `administrator_read.py` chama essa função com a identidade SOAP do worker; não existe rota extra na API da gestora.

Veja a [evidência sanitizada e os comandos de regressão](../../docs/sprint-2/evidence/s2-12.json). O recorte não compara snapshots, não produz `MATCHED`/`DIVERGENT`, não demonstra C2–C6 e não encerra o fluxo de aceite da Sprint 2.

## Conciliação — S2-13

Na raiz do repositório, com as mesmas imagens-base da S2-12, Docker Linux `amd64`
e Compose no PATH:

```powershell
py -B -m unittest discover -s tests/platform -p test_reconciliation.py -v
py -B deploy/platform/verify_reconciliation.py
```

No Linux, troque `py -B` por `python3 -B`. Use asserts habilitados e rode em série com os
outros verificadores. O segundo comando constrói as três imagens `:s2-13`, aplica as
migrações, provisiona as três identidades C1 e remove somente seus projetos e volumes
efêmeros. Para repetir um cenário, use seu nome (consulte `--help`).

| Cenário | Verificação |
|---|---|
| `incomplete_then_equal` | Sem snapshot terminal e sem registro no administrador: `NOT_READY`. Indisponibilidade não vira ausência; `NOT_FOUND` assinado persiste sem inventar snapshot. ACK não é suficiente. Dois workers concorrem pela consulta independente; um `MATCHED`, com data efetiva diferente da prevista. |
| `divergent` | Depois de um ACK legítimo, o [controle de laboratório](../../tests/reconciliation/lab_control.py) muda apenas a taxa no registro remoto. O `GetOperation` real e assinado traz o novo valor. Falha no commit não deixa recibo, resultado ou novo status; a tentativa nova encontra a diferença. `SETTLED`, histórico, boleta, lançamentos e saldos não mudam. O resultado sobrevive ao reinício; consulta REST sem permissão não revela dados. |
| `forbidden` | Um `FORBIDDEN` assinado do administrador bloqueia a leitura sem criar resultado de negócio nem alterar a projeção financeira. |

No ambiente operacional C1, aplique a migração 006 antes de trocar o worker de custódia.
Acrescente `deploy/platform/reconciliation.compose.yaml` após os overlays da S2-12 e
inicie `reconciliation-worker` além dos serviços da S2-12. Para uma rodada, use
`run --rm -T reconciliation-worker --once` (1 quando a rodada observa falha). O
worker usa timeout de conexão 3 s, troca 10 s e falhas transitórias com atrasos
iniciais de 1/2/4/8/16 s e jitter configurável (0 por padrão); a quinta falha
bloqueia. `NOT_FOUND` é uma observação autenticada, não falha técnica: nova
consulta é agendada após 16 s por padrão (`--absence-interval`).

`custody_snapshots` guarda o payload da resposta REST verificada; a revisão
remota permite identificar cada snapshot e seu recibo. Em `reconciliation_results`,
o digest e a boleta imutável identificam a fonte da gestora, a revisão referencia
o snapshot de custódia e o recibo SOAP referencia a resposta independente. A
consulta REST autenticada devolve apenas `reconciliationStatus` além dos dados
já previstos no contrato congelado. Terminais anteriores à migração sem captura
autenticada permanecem `NOT_READY`; não há backfill nem reabertura de conclusões
neste recorte.

[Evidência sanitizada e regressões](../../docs/sprint-2/evidence/s2-13.json).
