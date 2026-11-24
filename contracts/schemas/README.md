# Boleta v1

`boleta.schema.json` define os campos de entrada de `CREATE_OPERATION`. O emissor autenticado fornece `managerId` fora da boleta, para conferir a carteira. Na criação ainda não existe `operationId`: a identidade lógica é `(managerId, clientOrderId)`. A plataforma atribuirá UUID, `instructionVersion = 1`, `createdAt` e `updatedAt` somente após a criação. Esta sprint não implementa essa persistência. A boleta é imutável no MVP; atualização, cancelamento e versão 2 não são aceitos.

O schema restringe forma, escalas, limites decimais e enums. `tests/contracts/validate_boleta.py` aplica regras sem expressão no schema: datas reais e ordenadas, carteira autorizada, relações do cadastro, PU positivo, valor financeiro positivo, produto exato com `ROUND_HALF_UP` e overflow de `decimal(20,2)`. O parser rejeita propriedades JSON duplicadas antes da validação. Todos os valores financeiros permanecem strings, nunca floats binários.

`fixtures/boletas/references.json` é cadastro sintético explícito. A fixture válida usa o relógio financeiro simulado de 2026-11-19 (quinta-feira) e liquidação em 2026-11-20 (sexta-feira). O calendário experimental admite segunda a sexta sem feriados; isso não representa calendário real de mercado. A taxa não é usada para inferir PU. Mudanças de cadastros e do relógio nos futuros serviços exigirão validação equivalente no domínio.

Execute, a partir da raiz:

```text
docker build --platform linux/amd64 -f deploy/contracts/Dockerfile -t cafi-boleta:s1 .
docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges --mount "type=bind,source=<raiz-absoluta>,target=/work,readonly" -w /work -e PYTHONDONTWRITEBYTECODE=1 cafi-boleta:s1 python -m unittest discover -s tests/contracts -p test_boleta.py -v
docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges --mount "type=bind,source=<raiz-absoluta>,target=/work,readonly" -w /work -e PYTHONDONTWRITEBYTECODE=1 cafi-boleta:s1 python tests/contracts/check_boleta_schema.py
docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges --mount "type=bind,source=<raiz-absoluta>,target=/work,readonly" -w /work -e PYTHONDONTWRITEBYTECODE=1 cafi-boleta:s1 python tests/contracts/check_boleta_schema.py --invalid
```

O último comando deve falhar. A imagem deriva de `cafi-spikes:s1` preparada conforme ADR 0001; confira seu ID na evidência antes do build. O build baixa somente wheels fixadas por hash em `deploy/contracts/requirements-boleta.txt`. O motor valida Draft 2020-12 com verificação explícita de formato de data; regras financeiras e cadastrais continuam semânticas. Para executar apenas o validador semântico:

```text
python tests/contracts/validate_boleta.py fixtures/boletas/valid.json
```

O validador semântico usa a biblioteca padrão; a suíte também exige o motor fixado e falha se indisponível. A S1-09 foi iniciada fora da ordem nominal; a revalidação está em `docs/sprint-1/evidence/boleta.json`. Não demonstra persistência ou imutabilidade operacional.
