
## Add a custom authentication plugin to the Apache Pulsar Broker

    cd pulsarishare
    mvn clean install
    cd ..
    docker build -t "bdi/pulsar:3.0.0_{version}" .
    docker run --name="ApachePulsar" -d --restart=always -p 6650:6650 -p 8080:8080 -v /$(pwd)/volumes/data:/pulsar/data -v /$(pwd)/volumes/conf:/pulsar/conf bdi/pulsar:3.0.0_{version} bin/pulsar standalone
