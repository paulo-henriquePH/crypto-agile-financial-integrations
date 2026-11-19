# Boleta v1

`boleta.schema.json` define os campos de entrada de `CREATE_OPERATION`. O emissor autenticado fornece `managerId` fora da boleta, para conferir a carteira. Na criação ainda não existe `operationId`: a identidade lógica é `(managerId, clientOrderId)`. A plataforma atribuirá UUID, `instructionVersion = 1`, `createdAt` e `updatedAt` somente após a criação. Esta sprint não implementa essa persistência. A boleta é imutável no MVP; atualização, cancelamento e versão 2 não são aceitos.

O schema restringe forma, escalas, limites decimais e enums. `tests/contracts/validate_boleta.py` aplica regras sem expressão no schema: datas reais e ordenadas, carteira autorizada, relações do cadastro, PU positivo, valor financeiro positivo, produto exato com `ROUND_HALF_UP` e overflow de `decimal(20,2)`. O parser rejeita propriedades JSON duplicadas antes da validação. Todos os valores financeiros permanecem strings, nunca floats binários.

`fixtures/boletas/references.json` é cadastro sintético explícito. A fixture válida usa o relógio financeiro simulado de 2026-11-19 (quinta-feira) e liquidação em 2026-11-20 (sexta-feira). O calendário experimental admite segunda a sexta sem feriados; isso não representa calendário real de mercado. A taxa não é usada para inferir PU. Mudanças de cadastros e do relógio nos futuros serviços exigirão validação equivalente no domínio.

Execute, a partir da raiz:

```text
python -m unittest discover -s tests/contracts -p test_boleta.py -v
python tests/contracts/validate_boleta.py fixtures/boletas/valid.json
```

Este validador usa apenas a biblioteca padrão Python para execução isolada. O schema será também validado por ferramenta JSON Schema fixada quando a stack for aprovada; esta implementação não declara conformidade geral a JSON Schema. A S1-09 foi iniciada fora da ordem nominal por solicitação do usuário enquanto a S1-03 permanece pendente por indisponibilidade do Docker. Contratos dependentes da stack, assinaturas e TLS não estão aprovados.
