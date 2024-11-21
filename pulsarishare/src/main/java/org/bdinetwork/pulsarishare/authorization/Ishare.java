package org.bdinetwork.pulsarishare.authorization;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.*;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.UUID;
import java.util.stream.Collectors;

import org.apache.pulsar.broker.authentication.utils.AuthTokenUtils;
import org.bdinetwork.pulsarishare.IshareConfiguration;
import org.bdinetwork.pulsarishare.authorization.models.AuthRegistry;
import org.bdinetwork.pulsarishare.authorization.models.Delegation.*;
import org.bdinetwork.pulsarishare.authorization.models.DelegationEvidence;
import org.bdinetwork.pulsarishare.authorization.models.DelegationRequest;
import org.bdinetwork.pulsarishare.authorization.models.TokenResponse;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;

public class Ishare {

    private static final Logger log = LoggerFactory.getLogger(Ishare.class);

    private String serviceProviderId;
    private String serviceProviderPrivateKey;
    private String satelliteEori;
    private String satelliteUrl;
    private String certificate;

    public Ishare(IshareConfiguration conf) {
        this.satelliteEori = conf.getSatelliteId();
        this.satelliteUrl = conf.getSatelliteUrl();
        this.serviceProviderId = conf.getServiceProviderId();
        this.certificate = conf.getServiceProviderCertificate();
        this.serviceProviderPrivateKey = conf.getServiceProviderPrivateKey();
    }

    public String CreateClientAssertion(String audienceId) {
        RSAPrivateKey signingKey = GetSigningKey();

        String[] certificateChain = { Base64.getEncoder().encodeToString(getCertificate(this.certificate)) };
        JwtBuilder jwt = Jwts.builder()
                .setIssuer(serviceProviderId)
                .setAudience(audienceId)
                .claim("sub", serviceProviderId)
                .claim("jti", UUID.randomUUID().toString())
                .setNotBefore(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + (30 * 1000L)))
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setHeaderParam("alg", "RS256")
                .setHeaderParam("typ", "JWT")
                .setHeaderParam("x5c", certificateChain)
                .signWith(signingKey);

        return jwt.compact();
    }

    public String GetAccessToken(String audienceId, String tokenEndpoint) {
        URI url = URI.create(tokenEndpoint + "/connect/token");

        String clientAssertion = CreateClientAssertion(audienceId);
        log.error("clientAssertion {} ", clientAssertion);

        HashMap<String, String> parameters = new HashMap<>();
        parameters.put("grant_type", "client_credentials");
        parameters.put("scope", "iSHARE");
        parameters.put("client_id", serviceProviderId);
        parameters.put("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
        parameters.put("client_assertion", clientAssertion);

        String form = parameters.entrySet()
                .stream()
                .map(e -> e.getKey() + "=" + URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8))
                .collect(Collectors.joining("&"));

        log.error("form {} ", form);

        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(url)
                .headers("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(form))
                .build();
        HttpResponse<?> response;

        try {
            response = client.send(request, HttpResponse.BodyHandlers.ofString());

            log.error("response {}", response.body().toString());

            if (response.statusCode() != 200) {
                log.warn("Could not get access token from Authorization Registry");
                throw new RuntimeException();
            }
        } catch (IOException | InterruptedException e) {
            throw new RuntimeException(e);
        }

        TokenResponse tokenResponse = null;
        try {
            ObjectMapper mapper = new ObjectMapper();
            tokenResponse = mapper.readValue(response.body().toString(), TokenResponse.class);
        } catch (JsonProcessingException e) {
            log.warn("Could not get access token from API response: " + e);
        }

        if (tokenResponse == null) {
            log.warn("Could not get access token from API response");
            throw new RuntimeException();
        } else {
            log.info("Received token from Authorization Registry");
            return tokenResponse.AccessToken;
        }
    }

    public AuthRegistry getPartyAr(String partyEori) {

        log.error("satelliteUrl {} ", satelliteUrl);

        String accessToken = GetAccessToken(satelliteEori, satelliteUrl);

        URI url = URI.create(satelliteUrl + "/parties/" + partyEori);

        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(url)
                .headers("Authorization", "Bearer " + accessToken, "Content-Type", "application/json")
                .GET()
                .build();
        HttpResponse<?> response;

        try {
            response = client.send(request, HttpResponse.BodyHandlers.ofString());
            log.error("Parties info response {} ", response.body().toString());

        } catch (IOException | InterruptedException e) {
            throw new RuntimeException(e);
        }

        if (response.statusCode() != 200) {
            log.warn("Could not get party info (Http code %s)%n", response.statusCode());
            throw new RuntimeException();
        }

        ObjectMapper mapper = new ObjectMapper();
        String partyToken = null;
        try {

            JsonNode jsonNode = mapper.readTree(response.body().toString());
            partyToken = jsonNode.get("party_token").asText();
            log.error("partyToken {} ", partyToken);

        } catch (JsonProcessingException e) {
            log.warn("Could not get API response: " + e);
        }

        if (partyToken == null) {
            log.warn("Could not get access token from API response");
            throw new RuntimeException();
        }

        AuthRegistry authRegistry = null;
        Base64.Decoder decoder = Base64.getUrlDecoder();

        try {
            String[] chunks = partyToken.split("\\.");
            String payload = new String(decoder.decode(chunks[1]));

            JsonNode node = mapper.readTree(payload);
            JsonNode partyInfo = node.get("party_info");
            JsonNode authregisteryArray = partyInfo.get("authregistery");
            JsonNode authregistery = authregisteryArray.get(0);

            authRegistry = mapper.treeToValue(authregistery, AuthRegistry.class);

        } catch (JsonProcessingException e) {
            log.warn("Could not parse response: " + e);
        }
        log.info("authRegistry {} ", authRegistry.toString());

        return authRegistry;
    }

    public DelegationEvidence GetDelegationEvidence(AuthRegistry authRegistry, DelegationRequest delegationRequest)
            throws JsonProcessingException {

        String url = authRegistry.getAuthorizationRegistryUrl();
        String ArId = authRegistry.getAuthorizationRegistryID();

        URI uri = URI.create(url + "/delegation");

        String accessToken = GetAccessToken(ArId, url);

        ObjectMapper mapper = new ObjectMapper();
        mapper.setSerializationInclusion(Include.NON_NULL);
        mapper.enable(SerializationFeature.WRAP_ROOT_VALUE);
        String postRequest = mapper.writeValueAsString(delegationRequest);

        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(uri)
                .headers("Authorization", "Bearer " + accessToken, "Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(postRequest))
                .build();
        HttpResponse<?> response;

        try {
            response = client.send(request, HttpResponse.BodyHandlers.ofString());
            log.info("Delegation Evidence response {} ", response.body().toString());

        } catch (IOException | InterruptedException e) {
            throw new RuntimeException(e);
        }

        if (response.statusCode() != 200) {
            log.warn("Could not get delegation evidence from access token (Http code %s)%n", response.statusCode());

            throw new RuntimeException();
        }

        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode jsonNode;
        try {
            jsonNode = objectMapper.readTree(response.body().toString());
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
        String delegationEvidenceToken = jsonNode.get("delegation_token").asText();
        DelegationEvidence delegationEvidence = ParseDelegationEvidence(delegationEvidenceToken);
        return delegationEvidence;
    }

    public DelegationEvidence ParseDelegationEvidence(String delegationToken) {
        DelegationEvidence delegationEvidence = null;
        try {
            String[] chunks = delegationToken.split("\\.");
            Base64.Decoder decoder = Base64.getUrlDecoder();
            String payload = new String(decoder.decode(chunks[1]));

            ObjectMapper mapper = new ObjectMapper();
            JsonNode delegationEvidenceNode = mapper.readTree(payload).get("delegationEvidence");
            delegationEvidence = mapper.readValue(delegationEvidenceNode.toString(), DelegationEvidence.class);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
        return delegationEvidence;
    }

    public Boolean VerifyAccess(AuthRegistry authRegistry, DelegationRequest delegationRequest) {

        try {
            DelegationEvidence delegationEvidence = GetDelegationEvidence(authRegistry, delegationRequest);
            Boolean result = VerifyDelegationEvidence(delegationEvidence, delegationRequest);
            return result;

        } catch (RuntimeException e) {
            log.error("Unable to retrieve a valid delegation evidence {} ", e.getMessage());
            e.printStackTrace();

        } catch (JsonProcessingException e) {
            log.error("Unable to retrieve a valid delegation evidence {} ", e.getMessage());
            e.printStackTrace();
        }

        return false;

    }

    public boolean VerifyDelegationEvidence(DelegationEvidence delegationEvidence,
            DelegationRequest delegationRequest) {

        if (delegationEvidence == null) {
            log.warn("delegationEvidence %s was null%n");
            return false;
        }
        if (delegationRequest == null) {
            log.warn("delegationRequest %s was null%n");
            return false;
        }

        ArrayList<PolicySet> policySets = delegationRequest.getPolicySets();
        ArrayList<Policy> policies = policySets.get(0).getPolicies();
        Policy delegationRequestPolicy = policies.get(0);
        ArrayList<String> resourceIdentifiers = delegationRequestPolicy.getTarget().getResource().getIdentifiers();
        ArrayList<String> actions = delegationRequestPolicy.getTarget().getActions();

        if (policySets.size() > 1 || policies.size() > 1 || resourceIdentifiers.size() > 1 || actions.size() > 1) {
            // Could not verify, can only verify one
            log.warn(
                    "Could not verify deligation evidence, Arrays in the Delegation request can only be of length one");
            return false;
        }

        String issuer = delegationRequest.getPolicyIssuer();
        String subject = delegationRequest.getTarget().getAccessSubject();
        String resourceType = delegationRequestPolicy.getTarget().getResource().getType();
        String resourceIdentifier = resourceIdentifiers.get(0);
        String action = actions.get(0);

        if ((delegationEvidence.NotBefore > Instant.now().getEpochSecond()) ||
                (delegationEvidence.NotOnOrAfter <= Instant.now().getEpochSecond())) {
            log.warn("NotBefore > now or NotOnOrAfter <= now in delegationToken %s%n", delegationEvidence);
            return false;
        }

        if (issuer != null && !issuer.equals(delegationEvidence.PolicyIssuer)) {
            log.warn("Access token aud %s does not match the policyIssuer in delegationToken %s%n", issuer,
                    delegationEvidence);
            return false;
        }

        Policy delegationEvidencePolicy = delegationEvidence.PolicySets.get(0).Policies.get(0);
        if (subject != null && !subject.equals(delegationEvidence.Target.AccessSubject) &&
                !delegationEvidencePolicy.Target.Environment.ServiceProviders.contains(subject)) {
            log.warn(
                    "Access token aud %s does not match the target (AccessSubject or ServiceProvider) in delegationToken %s%n",
                    subject, delegationEvidence);
            return false;
        }

        if (delegationEvidence.PolicySets.get(0).MaxDelegationDepth < 0) {
            log.warn("Invalid max delegation depth in delegationToken %s, should be >= 0%n", delegationEvidence);
            return false;
        }

        if (resourceType != null && !resourceType.equals(delegationEvidencePolicy.Target.Resource.Type)) {
            log.warn("Invalid resource type in delegationToken %s, should be %s%n", delegationEvidence, resourceType);
            return false;
        }

        if (resourceIdentifier != null &&
                !delegationEvidencePolicy.Target.Resource.Identifiers.contains(resourceIdentifier)) {
            if (!delegationEvidence.PolicySets.get(0).Policies.get(0).Target.Resource.Identifiers.contains("*")) {
                log.warn("Invalid resource identifier in delegationToken %s, should be %s%n", delegationEvidence,
                        resourceIdentifier);
                return false;
            }
        }

        if (action != null && !delegationEvidencePolicy.Target.Actions.contains(action)) {
            log.warn("Invalid policy action in delegationToken %s, should be %s%n", delegationEvidence, action);
            return false;
        }

        String rootEffect = delegationEvidencePolicy.Rules.get(0).Effect;

        return rootEffect.equalsIgnoreCase("Permit");
    }

    private byte[] getCertificate(String param) {
        try {
            final byte[] privateKeyFile = AuthTokenUtils.readKeyFromUrl(param);
            PemReader pemReader = new PemReader(new InputStreamReader(new ByteArrayInputStream(privateKeyFile)));
            PemObject pemObject = pemReader.readPemObject();
            pemReader.close();
            return pemObject.getContent();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public PublicKey GetX509PublicKey(){
        PublicKey pubKey = null;
        try{
            byte[] byteKey = getCertificate(this.certificate);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate x509Certificate = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(byteKey));
            pubKey = x509Certificate.getPublicKey();
        }catch (CertificateException e) {
            throw new RuntimeException(e);
        }

        return pubKey;
    }

    private RSAPrivateKey GetSigningKey() {
        java.security.Security.addProvider(
                new org.bouncycastle.jce.provider.BouncyCastleProvider());

        KeyFactory kf;
        try {
            kf = KeyFactory.getInstance("RSA");
            byte[] certificate = getCertificate(this.serviceProviderPrivateKey);
            PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(certificate);
            KeyFactory factory = KeyFactory.getInstance("RSA", "BC");
            return (RSAPrivateKey) kf.generatePrivate(privateKeySpec);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (NoSuchProviderException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

}
