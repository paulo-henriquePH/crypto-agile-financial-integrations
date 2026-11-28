# S2-03 — gate de transporte

Na raiz, com Git, PowerShell e Docker Linux `amd64` no `PATH`, prepare `cafi-soap:s1` conforme [S2-02](../s2-02/README.md). Em seguida:

```powershell
docker build --platform linux/amd64 -t cafi-transport:s2-03 spikes/s2-03
powershell -NoProfile -File spikes/s2-03/verify.ps1 -BodyProof
powershell -NoProfile -File spikes/s2-03/verify.ps1
```

O primeiro verificador repete S2-02 na **imagem do transporte**. O segundo exige seis trocas positivas e nove rejeições específicas por troca. Falhas não esperadas, timeout ou erro do processo filho impedem sucesso. [Resultado dos parsers](../../docs/sprint-2/evidence/s2-03-body.json) e [observações por ponta e negativo](../../docs/sprint-2/evidence/s2-03.json). Saída 0 em ambos. O transporte foi repetido com nova PKI, com resultado sanitizado idêntico.

`transport.py` implementa o cliente `Endpoint.post` e o servidor `Endpoint.serve`: recebem o canal OpenSSL diretamente, usam h11 para framing e entregam bytes ao receptor. O handler e a política de rota/tipo/status são injetados. Uma conexão aceita um POST de tamanho conhecido e termina; não há descoberta de serviço, pool ou framework web adicional. `gate.py` fornece políticas locais, sockets TCP, PKI, corpos e handlers de laboratório. Cada conexão tem novo processo servidor (`spawn`), novo socket, `SSL_CTX` e `SSL`; o cliente executa no processo do runner. A comunicação de controle com o filho transporta somente endereço de escuta e resultado, nunca a mensagem REST/SOAP.

| Cliente → servidor | Envio | Retorno |
|---|---|---|
| Gestora → plataforma | `POST /v1/operations`, JSON | `201`, `CREATE_OPERATION_RESULT` |
| Plataforma → custodiante | `POST /v1/instructions`, JSON | `202`, `SUBMIT_INSTRUCTION_RESULT` |
| Plataforma → administrador | `POST /soap`, SOAP 1.2 document/literal, ação `urn:cafi:administrator:v1:RegisterOperation` | `200`, `REGISTER_OPERATION_RESULT` |

O servidor verifica o envelope ECDSA recebido do corpus congelado e só então devolve a resposta estática, também verificada no cliente. Cada receptor vincula o SAN exato, verificado pela API OpenSSL, ao participante e às chaves de mensagem autorizadas localmente; exige tipo, destinatário e `senderId` esperados. Nenhuma chave do corpo é usada como âncora. O parser S2-02 recebe os bytes sem transformação e seu callback recebe o mesmo conteúdo verificado. O gate confere também a igualdade dos corpos recebidos com o corpus nos dois sentidos.

**Negativos:** CA do servidor ou cliente não confiável, nome do servidor errado, certificado ausente, outro participante certificado pela CA correta, grupos sem interseção, cliente restrito a TLS 1.2, suíte sem interseção e `senderId` conflitante (resposta assinada do outro participante enviada como requisição em conexão autenticada). Exige o motivo de falha na ponta responsável e nenhum consumo de corpo nas duas pontas. O cenário híbrido altera só o estabelecimento de chaves.

**Proveniência e limites:** execução pré-commit sobre `2259e122f581b6b772e9789b710d6ee99e551257` mais os arquivos da proposta. A revisão Git na evidência identifica o checkout; os hashes são dos bytes executados, inclusive finais de linha. A imagem é identificada pelo ID local; a base é a imagem da prova de parsers e a única dependência adicional tem wheel fixado por hash. Os processos compartilham contêiner, UID e loopback com rede externa desabilitada; a PKI é temporária em tmpfs privado. Essa topologia prova negociação e autenticação, não isolamento de segredos entre serviços implantados. Os vetores estáticos não são comandos vigentes: validade temporal, autorização de carteira, correlação operacional, consultas/Faults na rede e persistência ficam para os endpoints. Não há medição de desempenho.
