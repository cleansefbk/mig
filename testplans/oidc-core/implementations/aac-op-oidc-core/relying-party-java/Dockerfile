FROM ubuntu:22.04

COPY ./src /tmp/src
COPY ./pom.xml /tmp/pom.xml
WORKDIR /tmp

RUN apt-get update && apt-get install git maven openjdk-11-jdk -y

RUN mvn package

#RUN mvn compiler:compile
RUN mvn package
VOLUME ["/data"]

EXPOSE 4200

#ENTRYPOINT ["mvn", "spring-boot:run"]
