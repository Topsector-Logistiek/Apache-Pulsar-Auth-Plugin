package org.bdinetwork.pulsarishare.authorization;

import static java.util.Objects.requireNonNull;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.UnsupportedJwtException;

import java.io.IOException;
import java.util.Set;
import java.util.concurrent.CompletableFuture;

import org.apache.pulsar.broker.ServiceConfiguration;
import org.apache.pulsar.broker.authentication.AuthenticationDataSource;
import org.apache.pulsar.broker.authentication.utils.AuthTokenUtils;
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
import org.bdinetwork.pulsarishare.IshareConfiguration;
import org.bdinetwork.pulsarishare.authorization.models.AuthRegistry;
import org.bdinetwork.pulsarishare.authorization.models.DelegationRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class IshareAuthorizationProvider implements AuthorizationProvider {
    private static final Logger log = LoggerFactory.getLogger(IshareAuthorizationProvider.class);

    static final String HTTP_HEADER_NAME = "Authorization";
    static final String HTTP_HEADER_VALUE_PREFIX = "Bearer ";
    static final String HTTP_HEADER_DELEGATION_TRAIL_NAME = "Delegation-trail";

    private JwtParser parser;
    private JwtParser internalTokenParser;
    
    protected PulsarResources pulsarResources;
    private IshareConfiguration ishareConf;
    private Ishare ishare;
    private String ishareConcept;
    private String ishareActionPrefix;
    private String serviceProviderId;
    private AuthRegistry defaulAuthRegistry;

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
        
        this.pulsarResources = pulsarResources;

        this.ishareConf = new IshareConfiguration(conf);
        this.ishare = new Ishare(ishareConf);

        this.serviceProviderId = ishareConf.getServiceProviderId();

        String internalTokenKey = (String) ishareConf.getProperty("internaltokenSecretKey");
        byte[] validationKey = AuthTokenUtils.readKeyFromUrl(internalTokenKey);

        this.ishareConcept = ishareConf.getConcept();
        this.ishareActionPrefix = ishareConf.getActionPrefix();

        String authorizationRegistryUrl = ishareConf.getAuthorizationRegistryUrl();
        String authorizationRegistryId = ishareConf.getAuthorizationRegistryId();
        defaulAuthRegistry = new AuthRegistry(authorizationRegistryId, authorizationRegistryUrl);

        parser = Jwts.parserBuilder().setSigningKey(ishare.GetX509PublicKey()).build();
        internalTokenParser = Jwts.parserBuilder().setSigningKey(validationKey).build();

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

    private String getDelegatedEori(AuthenticationDataSource authenticationData) {
        String delegatedEori = null;

        if (authenticationData.hasDataFromHttp()) {
            delegatedEori = authenticationData.getHttpHeader(HTTP_HEADER_DELEGATION_TRAIL_NAME);
        }

        return delegatedEori;
    }

    private Jws<Claims> parseToken(String jwtToken) {
        Jws<Claims> claim;
        try {
            claim = parser.parseClaimsJws(jwtToken);
        } catch (UnsupportedJwtException exception) {
            claim = internalTokenParser.parseClaimsJws(jwtToken);
        }
        return claim;
    }

    private String getTokenAudience(AuthenticationDataSource authenticationData) {
        String jwtToken = getToken(authenticationData);
        Jws<Claims> claim = parseToken(jwtToken);

        return claim.getBody().getAudience().trim();
    }

    private CompletableFuture<Boolean> isBrokerAdmin(AuthenticationDataSource authenticationData) {
        String jwtToken = getToken(authenticationData);
        Jws<Claims> claim = parseToken(jwtToken);

        String jwtTokenAudiance = claim.getBody().getAudience().trim();
        String jwtTokenIssuer = claim.getBody().getIssuer().trim();
        String jwtTokenSubject = claim.getBody().getSubject().trim();

        if (jwtTokenAudiance.equals(this.serviceProviderId) && jwtTokenIssuer.equals(this.serviceProviderId)
                && jwtTokenSubject.equals(this.serviceProviderId)) {
            return CompletableFuture.supplyAsync(() -> true);
        }
        return CompletableFuture.supplyAsync(() -> false);
    }

    private CompletableFuture<Boolean> checkAccess(AuthenticationDataSource authenticationData, String action,
            String topicName, String namespace) {

        if (!namespace.startsWith("EU.EORI")) {
            log.info("Internal namespace {}, check access with local certificate", namespace);
            return CompletableFuture.supplyAsync(() -> false);
        }
        if (topicName.startsWith("__")) {
            log.info("Internal topic {}, check access with local certificate", namespace);
            return CompletableFuture.supplyAsync(() -> false);
        }

        String clientId = getTokenAudience(authenticationData);

        String delegationEori = getDelegatedEori(authenticationData);
        log.info("delegationEori {}", delegationEori);

        String policyDecodedId = namespace + "#" + topicName;
        String accessSubject = clientId + "#" + policyDecodedId;

        if (delegationEori != null) {
            AuthRegistry authRegistry = ishare.getPartyAr(delegationEori);

            accessSubject = clientId + "#" + policyDecodedId;

            DelegationRequest delegationRequest = new DelegationRequest(accessSubject, ishareConcept, policyDecodedId,
                    "*", action, delegationEori, serviceProviderId);
            Boolean accessGranted = ishare.VerifyAccess(authRegistry, delegationRequest);

            if (!accessGranted) {
                log.info("Client is NOT authorised to act on behalf of {}", delegationEori);
                return CompletableFuture.supplyAsync(() -> false);
            }
            log.info("Client is authorised to act on behalf of {}", delegationEori);

            accessSubject = delegationEori + "#" + policyDecodedId;

        }

        DelegationRequest delegationRequest = new DelegationRequest(accessSubject, ishareConcept, policyDecodedId, "*",
                action, namespace, serviceProviderId);
        Boolean accessGranted = ishare.VerifyAccess(defaulAuthRegistry, delegationRequest);

        if (!accessGranted) {
            log.info("Topic owner {} denied access to {} for topic {}", namespace, clientId, topicName);
            return CompletableFuture.supplyAsync(() -> false);
        }
        log.info("Client is authorised to access the topic");

        return CompletableFuture.supplyAsync(() -> accessGranted);
    }

    @Override
    public void close() throws IOException {
        // No-op
    }

    @Override
    public CompletableFuture<Boolean> canProduceAsync(TopicName topicName, String role,
            AuthenticationDataSource authenticationData) {
        return checkAccess(authenticationData, ishareActionPrefix.concat("publish"),
                topicName.getLocalName(), topicName.getNamespacePortion());
    }

    @Override
    public CompletableFuture<Boolean> canConsumeAsync(TopicName topicName, String role,
            AuthenticationDataSource authenticationData, String subscription) {
        return checkAccess(authenticationData, ishareActionPrefix.concat("subscribe"),
                topicName.getLocalName(), topicName.getNamespacePortion());
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

        try {

            CompletableFuture<Boolean> isBrokerAdmin = isBrokerAdmin(authData);

            switch (operation) {
                case CONSUME:
                case SUBSCRIBE:
                    CompletableFuture<Boolean> canConsume = canConsumeAsync(topic, role, authData, "");
                    return isBrokerAdmin.thenCombine(canConsume, (a, b) -> a || b);
                case PRODUCE:
                    CompletableFuture<Boolean> canProduce = canProduceAsync(topic, role, authData);
                    return isBrokerAdmin.thenCombine(canProduce, (a, b) -> a || b);
                default:
                    return isBrokerAdmin;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return CompletableFuture.supplyAsync(() -> false);
    }

    @Override
    public CompletableFuture<Boolean> allowTopicPolicyOperationAsync(TopicName topic, String role, PolicyName policy,
            PolicyOperation operation, AuthenticationDataSource authData) {
        return isBrokerAdmin(authData);
    }
}
