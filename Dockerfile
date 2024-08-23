FROM gradle:8.10.0-jdk17-alpine AS build
COPY --chown=gradle:gradle . /home/gradle/src
WORKDIR /home/gradle/src
RUN gradle clean build -x test --no-daemon


# Use the official OpenJDK image from the Docker Hub
FROM eclipse-temurin:17.0.12_7-jre-alpine

# Set the working directory inside the container
WORKDIR /home/gradle/src

# Copy the JAR file into the container
COPY build/libs/cc-auth-service-0.0.1-SNAPSHOT.jar app.jar

# Expose the port your application will run on
EXPOSE 8080

# Run the JAR file
ENTRYPOINT ["java", "-jar", "app.jar"]