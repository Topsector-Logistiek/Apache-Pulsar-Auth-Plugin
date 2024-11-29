
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
- ishareSatelliteId=EU.EORI.NLDILSATTEST1
- ishareSatelliteUrl=https://dilsat1-mw.pg.bdinetwork.org

### iShare Authorisation Registry 
The default iShare Authorisation Registry to use
- ishareAuthorizationRegistryId=EU.EORI.NL000000004
- ishareAuthorizationRegistryUrl=https://ar.isharetest.net

The default values used in the Delegation Evidence policies
- ishareConcept=http://rdfs.org/ns/void#Dataset
- ishareActionPrefix=BDI.

### Identity of the service provider (The operator of the Pulsar Broker)
- ishareServiceProviderId=EU.EORI.NL000000000
- superUserRoles=EU.EORI.NL000000000
- ishareServiceProviderCertificate=file:///pulsar/conf/pub.pem
- ishareServiceProviderPrivateKey=file:///pulsar/conf/priv.key
- tokenPublicKey=file:///pulsar/conf/tokenPublicKey.txt

The pub.pem, priv.key and tokenPublicKey.txt can be generated from a pkcs12 key file with the following commands:
```bash
$ openssl pkcs12 -in key.p12 -clcerts -nokeys | openssl x509 -pubkey -noout -outform der | awk 'NR>2 { sub(/\r/, ""); printf "%s",last} { last=$0 }' | base64 --decode > tokenPublicKey.txt
$ openssl pkcs12 -in key.p12 -clcerts -nokeys -out pub.pem
$ openssl pkcs12 -in key.p12 -nocerts -nodes | openssl rsa > priv.key
```

### Internal broker communication
Communication between the different modules of Apache Pulsar requires authentication aswell. Therefor a token and key need to be generated and referenced.

- brokerClientAuthenticationParameters=file:///pulsar/conf/pulsar-broker-proxy-token.txt
- internaltokenSecretKey=file:///pulsar/conf/pulsar-broker-proxy-key.txt

The token needs to be a HS512 JWT with the iss, sub and aud field set to the eori number of the Super user. For example: 
```json
{
  "iss": "EU.EORI.NL000000000",
  "iat": 1718875881,
  "exp": 4085631102,
  "aud": "EU.EORI.NL000000000",
  "sub": "EU.EORI.NL000000000"
}
```
For demo purposes a key (>= 512 bits) and token can be generated [here](http://jwtbuilder.jamiekurtz.com/)

## Run the Apache Pulsar Broker with the iShare authorisation plugin
```bash
$ docker run --name "ApachePulsar" -d --restart "always" -p 6650:6650 -p 8080:8080 -v /$(pwd)/volumes/data:/pulsar/data -v /$(pwd)/volumes/conf:/pulsar/conf bdi/pulsar:3.0.0_{version}
```


## Run an iShare token endpoint
In order to subscribe to a topic, an access token must be provided. This access token can be obtained from an iShare token endpoint which must be configured with the same certificate as used to configure the Pulsar Broker.

Instructions and a docker image for this are available at: https://github.com/POORT8/Poort8.Ishare.Common
