# Build stage: compile and package with the bundled Maven wrapper.
FROM eclipse-temurin:25-jdk AS build
WORKDIR /src
COPY .mvn .mvn
COPY mvnw pom.xml ./
# Strip Windows line endings in case the wrapper was checked out with CRLF.
RUN sed -i 's/\r$//' mvnw && chmod +x mvnw && ./mvnw -B -q dependency:go-offline
COPY src src
RUN ./mvnw -B -q package -DskipTests && cp target/*.jar /app.jar

# Run stage: JRE only.
FROM eclipse-temurin:25-jre
COPY --from=build /app.jar /app.jar
# Hosting platforms pass the port in $PORT; fall back to 8080 locally.
ENV PORT=8080
EXPOSE 8080
ENTRYPOINT ["sh", "-c", "exec java -XX:MaxRAMPercentage=75 -XX:+UseSerialGC -Dserver.port=${PORT} -jar /app.jar"]
