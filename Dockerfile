FROM clipse-temurin:21-jdk

WORKDIR /gateway

COPY target/gateway.jar gateway.jar

EXPOSE 8090

ENTRYPOINT ["java", "-jar", "gateway.jar"]