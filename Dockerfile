FROM maven AS build
ADD . /log4jpwn
WORKDIR /log4jpwn
# RUN mvn clean compile assembly:single
RUN mvn dependency:copy-dependencies -DoutputDirectory=dep -Dhttps.protocols=TLSv1.2
RUN mvn clean package
RUN mkdir log-dep 
RUN mv dep/log4j-api-2.14.0.jar dep/log4j-core-2.14.0.jar log-dep

FROM gcr.io/distroless/java:11
# COPY --from=build /log4jpwn/target/log4jpwn-1.0-SNAPSHOT-jar-with-dependencies.jar /log4jpwn.jar
COPY --from=build /log4jpwn/target/log4jpwn-1.0-SNAPSHOT.jar /log4jpwn.jar
COPY --from=build /log4jpwn/dep /dep 
COPY --from=build /log4jpwn/log-dep /log-dep

ENV PWN="CVE-2021-44228"

EXPOSE 8080

# ENTRYPOINT ["java", "-jar", "/log4jpwn.jar"]
ENTRYPOINT [ "java", "-cp", "./log4jpwn.jar:dep/*", "com.sensepost.log4jpwn.App2" ]

