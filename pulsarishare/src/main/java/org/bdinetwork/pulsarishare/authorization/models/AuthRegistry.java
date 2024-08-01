package org.bdinetwork.pulsarishare.authorization.models;

import com.fasterxml.jackson.annotation.JsonProperty;
import javax.annotation.Nullable;



public class AuthRegistry {
    @JsonProperty("authorizationRegistryName")
    public @Nullable String AuthorizationRegistryName;
    @JsonProperty("authorizationRegistryID")
    public @Nullable String AuthorizationRegistryID;
    @JsonProperty("authorizationRegistryUrl")
    public @Nullable String AuthorizationRegistryUrl;
    @JsonProperty("dataspaceID")
    public @Nullable String DataspaceID;
    @JsonProperty("dataspaceName")
    public @Nullable String DataspaceName;

    public AuthRegistry(){
        
    }

    public AuthRegistry(String authorizationRegistryID, String authorizationRegistryUrl){
        this.AuthorizationRegistryID = authorizationRegistryID;
        this.AuthorizationRegistryUrl = authorizationRegistryUrl;
    }

    @Nullable
    public String getAuthorizationRegistryName() {
        return AuthorizationRegistryName;
    }
    public void setAuthorizationRegistryName(@Nullable String authorizationRegistryName) {
        AuthorizationRegistryName = authorizationRegistryName;
    }
    @Nullable 
    public String getAuthorizationRegistryID() {
        return AuthorizationRegistryID;
    }
    public void setAuthorizationRegistryID(@Nullable String authorizationRegistryID) {
        AuthorizationRegistryID = authorizationRegistryID;
    }
    @Nullable 
    public String getAuthorizationRegistryUrl() {
        return AuthorizationRegistryUrl;
    }
    public void setAuthorizationRegistryUrl(@Nullable String authorizationRegistryUrl) {
        AuthorizationRegistryUrl = authorizationRegistryUrl;
    }
    @Nullable 
    public String getDataspaceID() {
        return DataspaceID;
    }
    public void setDataspaceID(@Nullable String dataspaceID) {
        DataspaceID = dataspaceID;
    }
    public String getDataspaceName() {
        return DataspaceName;
    }
    @Nullable 
    public void setDataspaceName(@Nullable String dataspaceName) {
        DataspaceName = dataspaceName;
    }

    
}
