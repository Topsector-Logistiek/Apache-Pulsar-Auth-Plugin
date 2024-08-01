
# Apache Pulsar 


## Prepair the packages

Pull and build the branch XYZ from: https://github.com/Topsector-Logistiek/Apache-Pulsar/tree/feature/websocket-enforce-token-timeout#build
Locate the pulsar-broker-common.jar and pulsar-websocket.jar file in the folder named 'target'of their respective project folders. And copy them to this project folder, or point the path in the Docker files to these locations.





## Add a custom authentication plugin to the Apache Pulsar Broker

Go to the pulsarishare folder:

```bash
$ cd pulsarishare
```

Run a mvn clean install: 
```bash
$ mvn clean install
```

Move to the folder with the dockerfile and build the image: 
```bash
$ cd ..
$ docker build -t "bdi/pulsar:3.0.0_{version}" .
```

Adjust the ishare configuration in the standalone.conf file (line 522)

Run the docker image:
```bash
$ docker run --name "ApachePulsar" -d --restart "always" -p 6650:6650 -p 8080:8080 -v /$(pwd)/volumes/data:/pulsar/data -v /$(pwd)/volumes/conf:/pulsar/conf bdi/pulsar:3.0.0_{version}
```
