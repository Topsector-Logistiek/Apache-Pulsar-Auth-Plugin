package org.bdinetwork.pulsarishare.authorization;

import static java.util.Objects.requireNonNull;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CompletableFuture;

import org.apache.commons.codec.binary.Base64;
import org.apache.pulsar.broker.ServiceConfiguration;
import org.apache.pulsar.broker.authentication.AuthenticationDataSource;
import org.apache.pulsar.broker.authorization.AuthorizationProvider;
import org.apache.pulsar.broker.resources.PulsarResources;
import org.apache.pulsar.common.naming.NamespaceName;
import org.apache.pulsar.common.naming.TopicName;
import org.apache.pulsar.common.policies.data.AuthAction;
import org.apache.pulsar.common.policies.data.NamespaceOperation;
import org.apache.pulsar.common.policies.data.PolicyName;
import org.apache.pulsar.common.policies.data.PolicyOperation;
import org.apache.pulsar.common.policies.data.TenantOperation;
import org.apache.pulsar.common.policies.data.TopicOperation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class IshareAuthorizationProvider implements AuthorizationProvider {
    private static final Logger log = LoggerFactory.getLogger(IshareAuthorizationProvider.class);

    static final String HTTP_HEADER_NAME = "Authorization";
    static final String HTTP_HEADER_VALUE_PREFIX = "Bearer ";

    static final String CONF_ISHARE_CLIENT_ID = "ishareClientId";
    static final String CONF_ISHARE_AUTHORIZATION_REGISTRY_ID = "ishareAuthorizationRegistryId";
    static final String CONF_ISHARE_CERTIFICATE = "ishareCertificate";

    private static final Base64 BASE_64 = new Base64(0);

    private JwtParser parser;

    public ServiceConfiguration conf;

    protected PulsarResources pulsarResources;

    private String clientId;
    private String authorizationRegistryId;

    public IshareAuthorizationProvider() {

    }

    public IshareAuthorizationProvider(ServiceConfiguration conf, PulsarResources resources)
            throws IOException {
        initialize(conf, resources);

    }

    @Override
    public void initialize(ServiceConfiguration conf, PulsarResources pulsarResources) throws IOException {
        requireNonNull(conf, "ServiceConfiguration can't be null");
        requireNonNull(pulsarResources, "PulsarResources can't be null");
        this.conf = conf;
        this.pulsarResources = pulsarResources;

        this.clientId = ((String) conf.getProperty(CONF_ISHARE_CLIENT_ID)).trim();
        this.authorizationRegistryId = (String) conf.getProperty(CONF_ISHARE_AUTHORIZATION_REGISTRY_ID);
        String certificate = (String) conf.getProperty(CONF_ISHARE_CERTIFICATE);

        log.info("clientId: {}", clientId);
        log.info("authorizationRegistryId: {}", authorizationRegistryId);

        try {

            byte[] byteKey = BASE_64.decode(certificate);
            X509EncodedKeySpec X509publicKey = new X509EncodedKeySpec(byteKey);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PublicKey key1 = kf.generatePublic(X509publicKey);

            parser = Jwts.parserBuilder().setSigningKey(key1).build();
        } catch (NoSuchAlgorithmException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

    }

    private String getToken(AuthenticationDataSource authenticationData) {
        String token = null;

        if (authenticationData.hasDataFromCommand()) {
            // Authenticate Pulsar binary connection
            token = authenticationData.getCommandData();
        } else if (authenticationData.hasDataFromHttp()) {
            // The format here should be compliant to RFC-6750
            // (https://tools.ietf.org/html/rfc6750#section-2.1). Eg: Authorization: Bearer
            // xxxxxxxxxxxxx
            String httpHeaderValue = authenticationData.getHttpHeader(HTTP_HEADER_NAME);
            if (httpHeaderValue != null && httpHeaderValue.startsWith(HTTP_HEADER_VALUE_PREFIX)) {
                // Remove prefix
                token = httpHeaderValue.substring(HTTP_HEADER_VALUE_PREFIX.length());
            }
        }

        return token;
    }

    private CompletableFuture<Boolean> isBrokerAdmin(AuthenticationDataSource authenticationData) {
        String jwtToken = getToken(authenticationData);
        Jws<Claims> claim = parser.parseClaimsJws(jwtToken);
        String jwtTokenAudiance = claim.getBody().getAudience().trim();
        String jwtTokenIssuer = claim.getBody().getIssuer().trim();
        String jwtTokenSubject = claim.getBody().getSubject().trim();

        if (jwtTokenAudiance.equals(clientId) && jwtTokenIssuer.equals(clientId) && jwtTokenSubject.equals(clientId)) {
            return CompletableFuture.supplyAsync(() -> true);
        }

        return CompletableFuture.supplyAsync(() -> false);
    }

    private CompletableFuture<Boolean> makeDelegation(AuthenticationDataSource authenticationData, String action,
            String decodedConcept, String decodedId) {
        log.info("makeDelega with authenticationData: {} action: {}, decodedConcept: {}, decodedId: {}",
                authenticationData.toString(), action, decodedConcept, decodedId);

        String jwtToken = getToken(authenticationData);
        Jws<Claims> claim = parser.parseClaimsJws(jwtToken);
        String jwtTokenAudiances = claim.getBody().getAudience();

        if (jwtTokenAudiances.isEmpty()) {
            return CompletableFuture.supplyAsync(() -> false);
            // Unauthorized("JWT token has no audience");
        }

        String accessSubject = jwtTokenAudiances;
        String serviceProvider = clientId;

        String delegationRequest = GenerateBasicDelegationRequest(
                authorizationRegistryId,
                accessSubject,
                decodedConcept,
                List.of(decodedId),
                List.of(action),
                List.of(serviceProvider),
                List.of("*"));

        try {
            return DelegationIsValid(delegationRequest);
            // return allow: Access granted

        } catch (Exception e) {
            // TODO: handle exception

            // return deny: Access denied
        }

        return CompletableFuture.supplyAsync(() -> false);
    }

    // Replace with Poort8 function:
    private CompletableFuture<Boolean> DelegationIsValid(String delegationRequest) throws Exception {
        return CompletableFuture.supplyAsync(() -> true);
    }

    private String GenerateBasicDelegationRequest(String policyIssuer,
            String accessSubject,
            String type,
            List<String> identifiers,
            List<String> actions,
            List<String> serviceProvider) {
        return GenerateBasicDelegationRequest(policyIssuer, accessSubject, type, identifiers, actions, serviceProvider,
                null);
    }

    private String GenerateBasicDelegationRequest(String policyIssuer,
            String accessSubject,
            String type,
            List<String> identifiers,
            List<String> actions,
            List<String> serviceProvider,
            List<String> attributes) {

        return "";

    }

    @Override
    public void close() throws IOException {
        // No-op
    }

    @Override
    public CompletableFuture<Boolean> canProduceAsync(TopicName topicName, String role,
            AuthenticationDataSource authenticationData) {
        return makeDelegation(authenticationData, "Afleverprofiel.Publish", topicName.toString(), "*");
    }

    @Override
    public CompletableFuture<Boolean> canConsumeAsync(TopicName topicName, String role,
            AuthenticationDataSource authenticationData, String subscription) {
        return makeDelegation(authenticationData, "Afleverprofiel.Subscribe", topicName.toString(), "*");
    }

    @Override
    public CompletableFuture<Boolean> canLookupAsync(TopicName topicName, String role,
            AuthenticationDataSource authenticationData) {
        CompletableFuture<Boolean> canConsume = canConsumeAsync(topicName, role, authenticationData, role);
        CompletableFuture<Boolean> canProduce = canProduceAsync(topicName, role, authenticationData);
        return canConsume.thenCombine(canProduce, (a, b) -> a || b);
    }

    @Override
    public CompletableFuture<Boolean> allowFunctionOpsAsync(NamespaceName namespaceName, String role,
            AuthenticationDataSource authenticationData) {
        return isBrokerAdmin(authenticationData);
    }

    @Override
    public CompletableFuture<Boolean> allowSourceOpsAsync(NamespaceName namespaceName, String role,
            AuthenticationDataSource authenticationData) {
        return isBrokerAdmin(authenticationData);
    }

    @Override
    public CompletableFuture<Boolean> allowSinkOpsAsync(NamespaceName namespaceName, String role,
            AuthenticationDataSource authenticationData) {
        return isBrokerAdmin(authenticationData);
    }

    @Override
    public CompletableFuture<Void> grantPermissionAsync(NamespaceName namespace, Set<AuthAction> actions, String role,
            String authDataJson) {
        if (log.isDebugEnabled()) {
            log.debug("Policies are read-only. Broker cannot do read-write operations");
        }
        throw new IllegalStateException("policies are in readonly mode");
    }

    @Override
    public CompletableFuture<Void> grantSubscriptionPermissionAsync(NamespaceName namespace, String subscriptionName,
            Set<String> roles, String authDataJson) {
        if (log.isDebugEnabled()) {
            log.debug("Policies are read-only. Broker cannot do read-write operations");
        }
        throw new IllegalStateException("policies are in readonly mode");
    }

    @Override
    public CompletableFuture<Void> revokeSubscriptionPermissionAsync(NamespaceName namespace, String subscriptionName,
            String role, String authDataJson) {
        if (log.isDebugEnabled()) {
            log.debug("Policies are read-only. Broker cannot do read-write operations");
        }
        throw new IllegalStateException("policies are in readonly mode");
    }

    @Override
    public CompletableFuture<Void> grantPermissionAsync(TopicName topicName, Set<AuthAction> actions, String role,
            String authDataJson) {
        if (log.isDebugEnabled()) {
            log.debug("Policies are read-only. Broker cannot do read-write operations");
        }
        throw new IllegalStateException("policies are in readonly mode");
    }

    @Override
    public CompletableFuture<Boolean> allowNamespaceOperationAsync(NamespaceName namespaceName, String role,
            NamespaceOperation operation, AuthenticationDataSource authData) {
        return isBrokerAdmin(authData);
    }

    @Override
    public CompletableFuture<Boolean> allowNamespacePolicyOperationAsync(NamespaceName namespaceName, PolicyName policy,
            PolicyOperation operation, String role, AuthenticationDataSource authData) {
        return isBrokerAdmin(authData);
    }

    @Override
    public CompletableFuture<Boolean> allowTenantOperationAsync(String tenantName, String role,
            TenantOperation operation, AuthenticationDataSource authData) {
        return isBrokerAdmin(authData);
    }

    @Override
    public CompletableFuture<Boolean> allowTopicOperationAsync(TopicName topic, String role, TopicOperation operation,
            AuthenticationDataSource authData) {
        return isBrokerAdmin(authData);
    }

    @Override
    public CompletableFuture<Boolean> allowTopicPolicyOperationAsync(TopicName topic, String role, PolicyName policy,
            PolicyOperation operation, AuthenticationDataSource authData) {
        return isBrokerAdmin(authData);
    }
}
