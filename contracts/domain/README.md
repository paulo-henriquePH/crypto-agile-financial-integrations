# Estados e eventos v1

A [tabela executável](transitions.json) traduz a SPEC §3. O estado inicial é `REGISTERED`; o primeiro evento tem sequência 1 e omite `previousState`. Erros de sintaxe não criam operação. Uma operação válida pode registrar `REGISTERED` e `VALIDATED` na mesma transação futura, mas ambos os eventos permanecem no modelo.

| Atual | Próximo | Origem do evento |
|---|---|---|
| REGISTERED | VALIDATED | PLATFORM |
| REGISTERED | REJECTED | PLATFORM; `rejectionOrigin = LOCAL` |
| VALIDATED | SENT | PLATFORM |
| SENT | RECEIVED | CUSTODIAN |
| RECEIVED | ACCEPTED ou REJECTED | CUSTODIAN; rejeição com `rejectionOrigin = CUSTODIAN` |
| ACCEPTED | PENDING_SETTLEMENT | CUSTODIAN |
| PENDING_SETTLEMENT | SETTLED ou SETTLEMENT_FAILED | CUSTODIAN |

`REJECTED`, `SETTLED` e `SETTLEMENT_FAILED` são terminais. Rejeição e falha de liquidação exigem motivo não vazio. Outros eventos não carregam motivo nem `rejectionOrigin`. `origin` identifica quem produz o fato financeiro, não o processo que armazena a projeção. Administrador não produz mudança no estado financeiro.

O [schema](../schemas/event.schema.json) define UUIDs de evento/operação, versão 1, sequência positiva, estado anterior/novo, origem e horário UTC. O replay usa biblioteca padrão e aplica também transições, origem compatível, datas reais, unicidade, continuidade e identidade constante. A verificação independente usa `jsonschema` 4.23.0 e `rfc3339-validator` 0.1.4 fixados: exige o formato `date-time` e rejeita data impossível. JSON Schema isolado não substitui as regras semânticas nem o parser contra chaves duplicadas.

## Sequência e recuperação

Este histórico é a projeção financeira completa de uma operação na plataforma, iniciada em 1; a sequência cresce sem lacunas e é distinta de timestamps. Timestamps não ordenam eventos entre processos. Cada evento tem ID imutável: uma repetição estruturalmente idêntica, com mesmo ID e sequência, é ignorada; mesmo ID ou posição com conteúdo diferente é conflito. Não se permite pular de SENT diretamente a SETTLED, mesmo se um snapshot informar o estado terminal.

O custodiante terá sequência própria por operação para seu histórico remoto, cujo início é RECEIVED. O adaptador futuro deve validar essa sequência de origem, consultar eventos faltantes e aplicar os fatos intermediários à projeção completa com posições locais subsequentes. Não comparar o contador remoto diretamente com o local nem reatribuir identidade a fatos já aplicados. Os contratos de consulta em S1-15 definirão a representação desse histórico remoto; este verificador não implementa seu transporte ou persistência.

Ao detectar lacuna ou resposta inconclusiva, manter o último estado conhecido e consultar o custodiante com mensagem nova. Conferir assinatura, correlação, operação e versão; recuperar os eventos intermediários em ordem antes de aceitar o snapshot. Se a consulta não resolver a lacuna, não avançar a projeção. Apenas ausência autenticada permite concluir que o registro não existe naquele instante; retransmissão futura permanece idempotente. Testes operacionais pertencem às sprints seguintes.

`deliveryStatus` (`PENDING`, `UNKNOWN`, `CONFIRMED`, `BLOCKED`) e `reconciliationStatus` (`NOT_READY`, `MATCHED`, `DIVERGENT`) são dimensões separadas, não eventos financeiros. Timeout muda entrega para `UNKNOWN` sem inventar rejeição ou transição. Uma operação SETTLED pode continuar DIVERGENT ou NOT_READY. O verificador recebe esses status separadamente e os devolve sem alterar o histórico financeiro.

## Verificação isolada

```text
py -3 -m unittest discover -s tests/contracts -p test_events.py -v
py -3 tests/contracts/validate_events.py fixtures/events/settled.json
```

Em Linux substitua `py -3` por `python3`. O corpus inclui sucesso, rejeições local/remota, falha de liquidação, timeout e conciliação independente, repetição ignorada, conflito, regressão, transição proibida, terminal e lacuna. Entradas inválidas no CLI geram saída não zero. Não há worker, banco ou histórico persistido.

Reprodução no ambiente aprovado, em PowerShell na raiz (imagem base `cafi-spikes:s1`; Docker no PATH):

```powershell
docker build --platform linux/amd64 -f deploy/contracts/Dockerfile -t cafi-events:s1 .
$opts = @('run','--rm','--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--mount',"type=bind,source=$((Get-Location).Path),target=/work,readonly",'-w','/work','-e','PYTHONDONTWRITEBYTECODE=1','cafi-events:s1')
docker @opts python -m unittest discover -s tests/contracts -p test_events.py -v
docker @opts python -m unittest discover -s tests/contracts -p test_boleta.py -v
docker @opts python tests/contracts/check_boleta_schema.py
docker @opts python tests/contracts/check_events_schema.py
docker @opts python tests/contracts/check_events_schema.py --invalid
docker @opts python tests/contracts/validate_events.py fixtures/events/settled.json
docker @opts python tests/contracts/validate_events.py fixtures/events/gap.json
```

As duas últimas verificações negativas (`--invalid` e `gap.json`) devem sair com código 1. A suíte valida as sequências inválidas semanticamente; nem toda sequência inválida contém evento inválido segundo o schema.

S1-10 foi executada sobre a base `462454e`, por autorização do usuário para prosseguir com trabalho independente do build. S1-03–08 permanecem pendentes; este artefato não aprova stack, criptografia ou TLS.

Verificação nesta task: os três métodos de teste passaram, incluindo os 13 arquivos do corpus e subcasos estruturais. O CLI aceitou `settled.json` com estado SETTLED e sequência 7; rejeitou `gap.json` com código de saída 1. `git diff --check` não apontou erros. Horários aceitos pelo verificador usam `Z` e até seis casas fracionárias, sem segundos intercalares; não determinam ordem da projeção.
