FROM --platform=linux/arm64 arm64v8/gradle:8.10-jdk17-jammy AS build 
COPY --chown=gradle:gradle . /home/gradle/src
WORKDIR /home/gradle/src
RUN gradle clean build --no-daemon


FROM --platform=linux/arm64 arm64v8/eclipse-temurin:17-jre
EXPOSE 8080
RUN mkdir /app
COPY --from=build /home/gradle/src/build/libs/cc-auth-service-0.0.1-SNAPSHOT.jar /app/
ENTRYPOINT ["java","-XX:+UnlockExperimentalVMOptions", "-XX:+UseContainerSupport", "-Djava.security.egd=file:/dev/./urandom","-jar","/app/cc-auth-service-0.0.1-SNAPSHOT.jar"]