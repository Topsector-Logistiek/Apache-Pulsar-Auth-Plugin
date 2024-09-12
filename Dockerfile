#Build the Apache Pulsar maven modules which contain the fix for enforcing access token expiration times, and build the modules they depend on
FROM maven:3.9.0-eclipse-temurin-19

#Certs required for building on a CGI laptop
COPY ZscalerRootCertificate-2048-SHA256.crt /usr/local/share/ca-certificates/ZscalerRootCertificate-2048-SHA256.crt
COPY ZscalerRootCertificate-2048-SHA256.der $JAVA_HOME/bin/ZscalerRootCertificate-2048-SHA256.der
RUN apt-get update && \
    apt-get install -y ca-certificates && \
    update-ca-certificates && \
    $JAVA_HOME/bin/keytool -noprompt -storepass changeit -import -trustcacerts -alias zscalerrootca -file $JAVA_HOME/bin/ZscalerRootCertificate-2048-SHA256.der -keystore $JAVA_HOME/lib/security/cacerts

WORKDIR /pulsar
#Clone and build the Apache Pulsar project containing the fix for enforcing access token expiration times
RUN git clone -b "feature/websocket-enforce-token-timeout" https://github.com/Topsector-Logistiek/Apache-Pulsar.git && \
    cd Apache-Pulsar && \
    mvn -pl pulsar-websocket,pulsar-broker-common -am install -DskipTests

#Copy and build the Apache Pulsar iShare authorisation plugin
COPY pulsarishare /pulsar/pulsarishare
RUN cd pulsarishare && \
    mvn clean install

#Include the build jar files in the Apache Pulsar image
FROM apachepulsar/pulsar:3.0.0

USER root
RUN rm /pulsar/lib/org.apache.pulsar-pulsar-websocket-3.0.0.jar && \
    rm /pulsar/lib/org.apache.pulsar-pulsar-broker-common-3.0.0.jar
COPY --from=0 pulsar/Apache-Pulsar/pulsar-websocket/target/pulsar-websocket.jar /pulsar/lib/org.apache.pulsar-pulsar-websocket-3.0.0.jar
COPY --from=0 pulsar/Apache-Pulsar/pulsar-broker-common/target/pulsar-broker-common.jar /pulsar/lib/org.apache.pulsar-pulsar-broker-common-3.0.0.jar
USER 10000

COPY --from=0 pulsar/pulsarishare/target/pulsarishare-1.0-SNAPSHOT.jar /pulsar/lib

CMD bin/pulsar standalone
