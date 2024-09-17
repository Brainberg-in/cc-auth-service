FROM --platform=linux/arm64 arm64v8/gradle:8.10.1-jdk-21-and-22-alpine AS build 
COPY --chown=gradle:gradle . /home/gradle/src
WORKDIR /home/gradle/src
RUN gradle clean build --no-daemon


FROM --platform=linux/arm64 arm64v8/eclipse-temurin:21-jre-alpine
EXPOSE 8080
COPY --from=build /home/gradle/src/build/libs/cc-auth-service-0.0.1-SNAPSHOT.jar /app/
# Install curl for health checks
RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["java","-XX:+UnlockExperimentalVMOptions", "-XX:+UseContainerSupport", "-Djava.security.egd=file:/dev/./urandom","-jar","/app/cc-auth-service-0.0.1-SNAPSHOT.jar"]