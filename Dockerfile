FROM --platform=linux/arm64 arm64v8/eclipse-temurin:21-jre-alpine
COPY build/libs/cc-auth-service-0.0.1-SNAPSHOT.jar /app/
RUN mkdir -p /usr/local/newrelic
ADD ./newrelic/newrelic.jar /usr/local/newrelic/newrelic.jar
ADD ./newrelic/newrelic.yml /usr/local/newrelic/newrelic.yml

EXPOSE 8080