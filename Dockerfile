# Stage 1: Build the application using a Gradle image
FROM gradle:8.10-jdk17-alpine AS builder

# Set the working directory
WORKDIR /app

# Copy the Gradle wrapper and settings files first, to leverage Docker cache
COPY gradlew gradlew
COPY gradle gradle
COPY build.gradle ./

# Download dependencies before copying the application source code (leverages Docker cache)
#RUN ./gradlew dependencies

# Now copy the application source code
COPY src src

# Build the application
RUN ./gradlew clean build --no-daemon

# Analyze dependencies using jdeps
RUN jdeps --print-module-deps --ignore-missing-deps -q build/libs/*.jar > /app/deps.info

# Stage 2: Create a custom JDK runtime using jlink
FROM eclipse-temurin:17.0.12_7-jdk-alpine AS jlink

# Set the working directory
WORKDIR /jlink

# Copy the built application from the builder stage
COPY --from=builder /app/build/libs/*.jar /app.jar

# Copy the jdeps output
COPY --from=builder /app/deps.info /app/deps.info

# Create a custom runtime image using jlink, based on the jdeps output
RUN jlink \
    --module-path $JAVA_HOME/jmods \
    --add-modules $(cat /app/deps.info),java.desktop,jdk.management,java.naming \
    --output /custom-java-runtime \
    --strip-debug \
    --compress 2 \
    --no-header-files \
    --no-man-pages

# Stage 3: Create the final minimal image
FROM alpine:latest

# Install necessary runtime dependencies
RUN apk add --no-cache libstdc++ libgcc

# Set the work directory
WORKDIR /opt/app

# Copy the custom runtime from the jlink stage
COPY --from=jlink /custom-java-runtime /opt/java/

# Copy the application JAR from the builder stage
COPY --from=builder /app/build/libs/*.jar /opt/app/app.jar

# Set the environment variable to use the custom JDK runtime
ENV PATH="/opt/java/bin:$PATH"

ARG SPRING_PROFILE
ENV SPRING_PROFILES_ACTIVE=${SPRING_PROFILE}
# Run the application
ENTRYPOINT ["java", "-jar", "app.jar"]
