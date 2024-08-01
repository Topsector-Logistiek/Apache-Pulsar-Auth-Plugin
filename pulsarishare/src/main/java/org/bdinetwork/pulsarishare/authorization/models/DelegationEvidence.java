package org.bdinetwork.pulsarishare.authorization.models;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonRootName;

import javax.annotation.Nullable;

import org.bdinetwork.pulsarishare.authorization.models.Delegation.TargetObject;
import org.bdinetwork.pulsarishare.authorization.models.Delegation.PolicySet;

import java.util.ArrayList;

@JsonRootName("delegationEvidence")
public class DelegationEvidence {
    @JsonProperty("notBefore")
    public @Nullable int NotBefore;
    @JsonProperty("notOnOrAfter")
    public @Nullable int NotOnOrAfter;
    @JsonProperty("policyIssuer")
    public @Nullable String PolicyIssuer;
    @JsonProperty("target")
    public @Nullable TargetObject Target;
    @JsonProperty("policySets")
    public @Nullable ArrayList<PolicySet> PolicySets;

    @Nullable
    public int getNotBefore() {
        return NotBefore;
    }

    public void setNotBefore(@Nullable int notBefore) {
        NotBefore = notBefore;
    }

    @Nullable
    public int getNotOnOrAfter() {
        return NotOnOrAfter;
    }

    public void setNotOnOrAfter(@Nullable int notOnOrAfter) {
        NotOnOrAfter = notOnOrAfter;
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