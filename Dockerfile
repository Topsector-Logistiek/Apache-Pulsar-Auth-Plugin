FROM apachepulsar/pulsar:3.0.0
COPY pulsarishare/target/pulsarishare-1.0-SNAPSHOT.jar /pulsar/lib
USER root
RUN rm /pulsar/lib/org.apache.pulsar-pulsar-websocket-3.0.0.jar
COPY pulsar-websocket.jar /pulsar/lib/org.apache.pulsar-pulsar-websocket-3.0.0.jar

RUN rm /pulsar/lib/org.apache.pulsar-pulsar-broker-common-3.0.0.jar
COPY pulsar-broker-common.jar /pulsar/lib/org.apache.pulsar-pulsar-broker-common-3.0.0.jar
USER 10000