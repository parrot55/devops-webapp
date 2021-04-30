FROM azul/zulu-openjdk-alpine:15
LABEL maintainer=patrick.roth@bfh.ch

COPY devops-webapp*.jar webapp/devops-webapp.jar

ENTRYPOINT ["java", "-jar", "webapp/devops-webapp.jar"]