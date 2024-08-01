package org.bdinetwork.pulsarishare.authorization.models;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonRootName;

import javax.annotation.Nullable;

import org.bdinetwork.pulsarishare.authorization.models.Delegation.*;

import java.util.ArrayList;
import java.util.Arrays;

@JsonRootName(value = "delegationRequest")
public class DelegationRequest {
    @JsonProperty("policyIssuer")
    public @Nullable String PolicyIssuer;
    @JsonProperty("target")
    public @Nullable TargetObject Target;
    @JsonProperty("policySets")
    public @Nullable ArrayList<PolicySet> PolicySets;

    public DelegationRequest(){

    }

    public DelegationRequest(String subject, String resourceType, String resourceIdentifier, String resourceAttribute, String action, String policyIssuer, String serviceProviderId) {

        TargetObject target = new TargetObject();
        target.setAccessSubject(subject);

        Resource resource = new Resource();
        resource.setType(resourceType);
        resource.setIdentifiers(new ArrayList<>(Arrays.asList(resourceIdentifier)));
        resource.setAttributes(new ArrayList<>(Arrays.asList(resourceAttribute)));

        Environment environment = new Environment();
        environment.setServiceProviders(new ArrayList<>(Arrays.asList(serviceProviderId)));

        TargetObject policyTarget = new TargetObject();
        policyTarget.setResource(resource);
        policyTarget.setActions(new ArrayList<>(Arrays.asList(action)));
        policyTarget.setEnvironment(environment);

        Rule rule = new Rule();
        rule.setEffect("Permit");

        Policy policy_1 = new Policy();
        policy_1.setTarget(policyTarget);
        policy_1.setRules(new ArrayList<>(Arrays.asList(rule)));

        PolicySet policySet = new PolicySet();
        policySet.setPolicies(new ArrayList<>(Arrays.asList(policy_1)));

        this.setPolicyIssuer(policyIssuer);
        this.setTarget(target);
        this.setPolicySets(new ArrayList<>(Arrays.asList(policySet)));
       
    }

    @Nullable
    public String getPolicyIssuer() {
        return PolicyIssuer;
    }

    public void setPolicyIssuer(@Nullable String policyIssuer) {
        PolicyIssuer = policyIssuer;
    }

    @Nullable
    public TargetObject getTarget() {
        return Target;
    }

    public void setTarget(@Nullable TargetObject target) {
        Target = target;
    }

    @Nullable
    public ArrayList<PolicySet> getPolicySets() {
        return PolicySets;
    }

    public void setPolicySets(@Nullable ArrayList<PolicySet> policySets) {
        PolicySets = policySets;
    }

    
}