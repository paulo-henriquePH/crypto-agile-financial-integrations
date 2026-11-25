# Verificação e evidências

## Sprint 1

O comando integrado verifica contratos, vetores e provas isoladas. Para reproduzir a entrega de referência, execute na raiz de um checkout confiável e limpo, com Git, PowerShell e Docker Engine em modo Linux `amd64`. Consulte os [pré-requisitos do runner](../scripts/verify-sprint1/README.md) antes de iniciar os builds.

```powershell
powershell -NoProfile -File scripts/verify-sprint1/verify.ps1
```

O [índice da Sprint 1](../docs/sprint-1/README.md) mapeia requisitos a artefatos e evidências. Os [testes de contrato](../tests/contracts/) e as [provas isoladas](../spikes/README.md) permitem verificações focadas. O verificador da sprint não inicia serviços do MVP.

## Próximas entregas

- Execute as verificações pertinentes ao escopo alterado. Em edição exclusivamente documental, confira os links e as referências; não apresente essa revisão como teste funcional.
- Para o aceite do MVP, use [T01–T14 na SPEC](../SPEC.md#8-verificação-e-critérios-de-entrega) e as [configurações C1–C6 e a metodologia no README](../README.md#metodologia-de-avaliação). Uma prova isolada não substitui a execução nos conectores.
- Registre comando, revisão ou estado da árvore, ambiente e resultado observado. Informe bloqueios, falhas e testes não executados. Não avance um critério de aceite obrigatório com falha ou skip.
- Preserve as evidências históricas e versione apenas seleções sanitizadas. Para os experimentos do MVP, vincule os resultados aos dados brutos, ao manifesto e aos parâmetros de coleta, conforme a [SPEC](../SPEC.md#7-observabilidade-e-avaliação).
