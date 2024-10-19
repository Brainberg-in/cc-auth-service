FROM --platform=linux/arm64 arm64v8/eclipse-temurin:21-jre-alpine
COPY build/libs/cc-auth-service-0.0.1-SNAPSHOT.jar /app/
EXPOSE 8080
ENTRYPOINT ["java","-XX:+UnlockExperimentalVMOptions", "-XX:+UseContainerSupport", "-Djava.security.egd=file:/dev/./urandom","-jar","/app/cc-auth-service-0.0.1-SNAPSHOT.jar"]