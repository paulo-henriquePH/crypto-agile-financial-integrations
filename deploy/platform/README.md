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

O papel de execução tem `INSERT,SELECT`, sem `UPDATE`/`DELETE` nas quatro tabelas. A transação segura travas transacionais PostgreSQL em namespaces distintos: ordem da gestora, depois ID de mensagem. Elas serializam inclusive chaves ainda inexistentes; colisão do hash da trava apenas serializa trabalho adicional. As identidades completas continuam protegidas por unicidade. O recibo guarda SHA-256 dos **bytes recebidos** e o resultado lógico; a identidade da ordem compara SHA-256 de JCS da boleta. O estado atual vem do último evento, e a sequência ordena a projeção. A criação lê sempre o evento 2. A intenção contém destinatário, payload e versão; envelope ainda não preparado, zero tentativas.

Para provar atualidade sem implementar o remetente futuro, **só o verificador** acrescenta um terceiro evento sintético, reinicia o serviço e compara a consulta nova com o replay da criação. Também insere uma operação de outro titular e remove a concessão no catálogo para testar sigilo. Essas intervenções não são funcionalidades do endpoint. [Resultado da execução](../../docs/sprint-2/evidence/s2-06.json).

Para repetir a regressão de inicialização dos parsers, execute `powershell -NoProfile -File scripts/verify-c1/verify.ps1`. Um processo Python novo sincroniza oito threads na primeira leitura JSON, na primeira leitura SOAP e em uma rodada mista. O teste confere que JSON não compila XSD e que o XSD é compilado uma única vez. No `lab.py verify`, os clientes também sincronizam a primeira assinatura e o envio em conexões mTLS distintas para o serviço recém-iniciado.
