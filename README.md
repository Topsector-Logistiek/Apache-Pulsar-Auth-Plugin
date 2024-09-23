
# Apache Pulsar 
This repository contains an Authorisation plugin for Apache Pulsar to support the iShare authorisations method

## Build the docker image
```bash
$ cd ..
$ docker build -t "bdi/pulsar:3.0.0_{version}" .
```
The images includes the iShare authorisation plugin in the Apache Pulsar image.

## Prepare the config file for the broker

Set the following variables in the standalone.conf configuration file:

### iShare Satellite
The default iShare satellite to use
ishareSatelliteId=EU.EORI.NLDILSATTEST1
ishareSatelliteUrl=https://dilsat1-mw.pg.bdinetwork.org

### iShare Authorisation Registry 
The default iShare Authorisation Registry to use
ishareAuthorizationRegistryId=EU.EORI.NL000000004
ishareAuthorizationRegistryUrl=https://ar.isharetest.net

The default values used in the Delegation Evidence policies
ishareConcept=http://rdfs.org/ns/void#Dataset
ishareActionPrefix=BDI.

### Identity of the service provider (The operator of the Pulsar Broker)
ishareServiceProviderId=EU.EORI.NL000000000
superUserRoles=EU.EORI.NL000000000
ishareServiceProviderCertificate=MIID0TCCArmgAwIBA.......
ishareServiceProviderPrivateKey=MIIEp.......
tokenPublicKey=data:;base64,MIIBIjAN......

### Internal broker communication
Communication between the different modules of Apache Pulsar requires authentication aswell. Therefor a token and key need to be generated and referenced.

brokerClientAuthenticationParameters=file:///pulsar/conf/pulsar-broker-proxy-token.txt
internaltokenSecretKey=file:///pulsar/conf/pulsar-broker-proxy-key.txt


## Run the Apache Pulsar Broker with the iShare authorisation plugin
```bash
$ docker run --name "ApachePulsar" -d --restart "always" -p 6650:6650 -p 8080:8080 -v /$(pwd)/volumes/data:/pulsar/data -v /$(pwd)/volumes/conf:/pulsar/conf bdi/pulsar:3.0.0_{version}
```
