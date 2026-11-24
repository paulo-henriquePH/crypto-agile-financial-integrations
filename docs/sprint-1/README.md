# Sprint 1 — contratos e provas isoladas

**Estado:** execução integrada aprovada sobre `d715c2c2980b34ddab6fe62322a6f5f569e669b1`; consolidação documental sujeita à revisão independente e ao commit do coordenador. Não é liberação do MVP nem aprovação para produção.

## Reprodução e evidência

Em checkout confiável e limpo, com Git, Windows PowerShell 5.1 ou PowerShell 7, Docker Engine Linux `amd64`, disco suficiente para dois builds completos e acesso à imagem base, fonte OpenSSL e wheels fixados:

```powershell
powershell -NoProfile -File scripts/verify-sprint1/verify.ps1
```

O [runner](../../scripts/verify-sprint1/README.md) explica política de execução, Linux/pwsh, fallback do Docker Desktop, rede no build, isolamento em runtime e contraprova opcional. Python e pip no host não são necessários. Os dois builds normais usam `--no-cache`, demoram e consomem disco; não removem cache. Dependência indisponível, falha ou skip obrigatório bloqueia o aceite.

A [seleção sanitizada da execução final](evidence/final-verification.json) registra checkout limpo, commit testado, snapshot, imagens e resultados: exit 0, zero skips, 69 testes, 27 mensagens estáticas/36 assinaturas e 27 novas/36 assinaturas, mais 15 testes nos vetores novos. ECDSA e ML-DSA foram executados e os grupos `x25519` e `X25519MLKEM768` observados em cliente e servidor, este último em duas invocações. O relatório completo por caso é local e ignorado em `.spikes/verify-sprint1/`; seu SHA-256 está na seleção.

O [integrated.json histórico](evidence/integrated.json) registra a execução anterior ao commit com `testedCommit: null` e a contraprova de entrada adulterada com saída 1; não é a execução final nem foi modificado. A referência independente [JavaScript JCS](../../contracts/vectors/json/evidence.json) e a [.NET XML](evidence/xml-c14n.json) são históricas, não executadas nem contadas pelo runner atual.

## Matriz requisito → artefato → verificação

Todas as linhas executáveis usam o comando integrado acima; as evidências específicas acrescentam contexto histórico.

| Requisito | Artefato | Evidência e limite |
|---|---|---|
| Escopo e ameaças | [baseline](scope.md), [ameaças](../security/threat-model.md) | Revisão documental; controles dependentes de serviços permanecem futuros. |
| Ambiente e stack | [pins](../../deploy/spikes/versions.json), [ADR](../adr/0001-stack.md) | Inventário e provas no relatório final; ADR histórica distingue APIs e CLI. |
| ECDSA / ML-DSA | [provas](../../spikes/signatures/), [ECDSA](evidence/ecdsa.json), [ML-DSA](evidence/ml-dsa.json) | Originais e negativos isolados; sem provedor de produção. |
| TLS e incompatibilidade | [harness](../../spikes/tls/), [X25519](evidence/tls-x25519.json), [híbrido](evidence/tls-hybrid.json) | mTLS e grupo observado, sem fallback; não comprova conectores. |
| Boleta, estados e eventos | [schemas](../../contracts/schemas/), [transições](../../contracts/domain/), [fixtures](../../fixtures/) | [Boleta](evidence/boleta.json), [eventos](evidence/events.json), testes atuais; não há persistência. |
| Envelope e perfis | [mensagens](../../contracts/messages/), [evidência](evidence/messages.json) | Contexto, correlação e perfis validados isoladamente. |
| Canonicalização | [JCS](../../contracts/vectors/json/), [XML](../../contracts/vectors/xml/), [JCS histórico](evidence/jcs.json), [XML histórico](evidence/xml-c14n.json) | Bytes e negativos; não comprova parsers dos serviços futuros. |
| REST plataforma e custodiante | [OpenAPI](../../contracts/openapi/), [plataforma](evidence/platform-openapi.json), [custodiante](evidence/custodian-openapi.json) | Schemas, referências e exemplos; sem endpoints executáveis. |
| SOAP administrador | [WSDL/XSD](../../contracts/soap/), [evidência](evidence/administrator-soap.json) | XSD, imports locais e carga Zeep; não comprova interoperabilidade de serviço. |
| Assinaturas dos contratos | [corpus](../../contracts/vectors/signed/), [evidência](evidence/signed-vectors.json) | Perfis e negativos sobre JSON/XML; apenas chaves públicas no corpus, relógio de referência fixo. |
| Integração e contraprova | [runner](../../scripts/verify-sprint1/), [final](evidence/final-verification.json), [histórica](evidence/integrated.json) | Final sobre commit limpo; contraprova no relatório histórico, não repetida nesta execução. |

As assinaturas dos exemplos estruturais REST, SOAP e de canonicalização são **ilustrativas**, não verificações criptográficas reais. O corpus S1-17 contém **27 mensagens e 36 assinaturas reais**.

## Congelamento e compatibilidade

A baseline congelada é a árvore do commit testado, abrangendo `contracts/`, fixtures e verificadores correspondentes. A seleção registra hashes SHA-256 dos arquivos centrais e dos manifestos/chaves públicas do corpus; o `snapshotSHA256` também compromete todos os hashes de entrada do runner. O relatório local registra cada hash individual. Os hashes são dos **bytes copiados do checkout testado**, não necessariamente dos blobs Git: conversão LF/CRLF altera o hash. Para comparar, reproduza o mesmo checkout e hash dos bytes, ou compare separadamente os blobs do commit; não normalize as fontes oficiais WSDL/XSD nem remova seus espaços originais. O manifesto do corpus inclui digests dos bytes canônicos decodificados, distintos dos hashes de arquivo.

Para qualquer mudança futura, revisar compatibilidade antes de aprovar: versão e campos obrigatórios/desconhecidos; enums, decimais, limites e estados; endpoints, ações, códigos e correlação; namespaces, XSD, imports e semântica JSON/XML; JCS/C14N e bytes assinados; algoritmos, perfil duplo, chaves e política; fixtures e consumidores. Alterações incompatíveis exigem versão/migração explícita, atualização dos vetores e repetição das verificações afetadas e da integração; não substituir silenciosamente a baseline.

## Limitações e próximos gates

CPython 3.13.11, OpenSSL 3.5.9, imagem por digest e dependências por hash são pins de laboratório, não recomendação de produção. `ctypes` é experimental e exige revisão de ABI, ownership, concorrência e erros. TLS híbrido muda o estabelecimento de chaves; autenticação mTLS continua tradicional, enquanto ML-DSA autentica a mensagem. A prova recusa incompatibilidade sem fallback; rollback de política não é automático. O host, CA, relógio e plataforma continuam fronteiras de confiança; proteção física/HSM e host comprometido não são resolvidos.

A stack foi validada nas PoCs, mas permanece **candidata e não aprovada para os serviços**; a escolha e a integração dos componentes de serviço exigem novas provas.

Não há serviços financeiros, CI declarada, banco, conectores operacionais, interoperabilidade de serviços, migração sob carga ou benchmark demonstrados. O WSDL carregado por cliente não prova troca real. T01–T14 e seis configurações nos adapters continuam gates do MVP; parcelas isoladas verificadas nesta sprint não substituem esses testes.
