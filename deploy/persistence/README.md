# Base de persistência C1 (S2-04)

Na raiz do checkout, com Python ≥ 3.10 no host, Docker Engine para Linux `amd64` e Compose com `up --wait`. No Windows use `py -3` no lugar de `python3` e disponibilize a CLI Docker no `PATH`.

```sh
python3 deploy/persistence/lab.py up demo
echo 'SELECT * FROM portfolio;' | python3 deploy/persistence/lab.py sql demo platform
python3 deploy/persistence/lab.py migrate demo
python3 deploy/persistence/lab.py restart demo
python3 deploy/persistence/lab.py down demo
python3 -B deploy/persistence/lab.py verify
```

Escolha um nome exclusivo por cenário. `up` cria/reutiliza o projeto `cafi-s2-<cenário>`, aguarda o PostgreSQL e aplica os cadastros. `restart` preserva os volumes. **`down` remove dados e credenciais do cenário nomeado.** Para retomar uma preparação interrompida, execute `up` com o mesmo nome; para reiniciar do zero, `down` e `up`. `verify` cria e limpa seus próprios projetos com nomes aleatórios. Nenhuma porta do banco é publicada no host.

No mesmo projeto Compose, cada futuro serviço usa o host `db`, porta `5432`, base e usuário com o mesmo nome (`platform`, `custodian`, `administrator`). Monte **apenas** `<serviço>_key:/run/db-secret:ro` no contêiner correspondente e leia `/run/db-secret/password` (arquivo modo `0600`, proprietário `postgres`, UID 999 na imagem fixada; compatibilizar o UID do processo consumidor). Os quatro arquivos aleatórios, inclusive o do operador `postgres`, são gerados em volumes Docker distintos, fora do checkout. O comando `sql` recebe SQL por stdin e conecta com o papel do serviço por TCP/SCRAM.

O operador é dono dos objetos; os serviços recebem `CONNECT` apenas na própria base e `SELECT` nos cadastros. O catálogo local de cada participante parte dos [dados sintéticos](../../fixtures/boletas/references.json). As migrações numeradas em `migrations/` são aplicadas em ordem, em transação por base, com trava e checksum do SQL normalizado para LF. Acrescentar uma nova migração para evoluir o esquema; não alterar uma já aplicada. Para tabelas exclusivas de um participante, condicionar o SQL à variável `psql` `service` e conceder explicitamente os privilégios de execução necessários. A infraestrutura não implementa eventos financeiros, outbox ou inbox.
