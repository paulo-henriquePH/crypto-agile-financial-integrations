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
Uma falha não gera rejeição financeira, não rearma o acompanhamento e não provoca retransmissão.
Respostas autenticadas e correlacionadas usam a mesma reserva transacional de IDs da API da gestora.
O worker guarda o digest SHA-256 dos bytes recebidos, não reserializados, e apenas os metadados
necessários para identificar o resultado. O [registro de recibos](../../services/platform/response_receipts.py)
usa a transação do chamador e não decide a ação de negócio. O custodiante do verificador observa o
digest dos bytes enviados sem salvar o envelope nos logs.
Recuperação de uma entrega inconclusiva, inclusive `UNKNOWN`, preenchimento de lacunas e política de
retentativas, é S2-10. SOAP e conciliação não estão neste recorte.
[Evidência sanitizada](../../docs/sprint-2/evidence/s2-09.json).
