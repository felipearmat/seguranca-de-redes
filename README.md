# Segurança de redes 2023

## Pentest com Kali contra ActiveMQ 5.15.15

Para construir e executar os containers que serão utilizados para esse pentest você deverá possuir p docker-ce instalado em seu computador com o plugin de docker-compose ativado. Com isso você pode executar o comando:

```shell
docker compose up
```

**Obs:** A construção do contâiner Kali poderá demorar alguns minutos dependendo da sua internet e da capacidade do seu computador, seja paciente.

O terminal atual apresentará as saídas dos dois containers.
Para acessar o container Kali, abra um novo terminal na mesma pasta deste projeto e execute o seguinte comando:

```shell
docker compose exec kali bash
```

Um terminal kali será iniciado, então você poderá executar os comandos presentes no documento deste projeto para prosseguir com o pentest.
