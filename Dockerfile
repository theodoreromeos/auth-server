FROM maven:3.9-eclipse-temurin-21 AS builder
WORKDIR /workspace

COPY mobility-common ./mobility-common
RUN mvn -f mobility-common/pom.xml -B -Dmaven.test.skip=true clean install

COPY mobility-authserver ./mobility-authserver
RUN mvn -f mobility-authserver/pom.xml -B -Dmaven.test.skip=true clean package

FROM eclipse-temurin:21-jre
WORKDIR /app
COPY --from=builder /workspace/mobility-authserver/target/*.jar app.jar
EXPOSE 9000 9001
ENTRYPOINT ["java","-jar","/app/app.jar"]