FROM maven:3.6.3-jdk-8 AS build

WORKDIR /usr/src/activemq

COPY . .

RUN mvn -DskipTests clean install

RUN unzip ./assembly/target/apache-activemq-5.15.15-bin.zip

FROM openjdk:8-jre-slim AS runtime

COPY --from=build /usr/src/activemq/apache-activemq-5.15.15 /opt/activemq

RUN chown -R root:root /opt/activemq

RUN chmod +x /opt/activemq/bin/activemq

EXPOSE 61616 8161

CMD ["/opt/activemq/bin/activemq", "console"]
