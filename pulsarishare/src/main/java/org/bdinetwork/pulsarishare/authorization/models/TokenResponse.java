package org.bdinetwork.pulsarishare.authorization.models;

import com.fasterxml.jackson.annotation.JsonProperty;
import javax.annotation.Nullable;

public class TokenResponse {
    @JsonProperty("access_token")
    public @Nullable String AccessToken;
    @JsonProperty("token_type")
    public @Nullable String TokenType;
    @JsonProperty("expires_in")
    public int ExpiresIn;
    @JsonProperty("scope")
    public @Nullable String Scope;

    @Nullable
    public String getAccessToken() {
        return AccessToken;
    }

    @Nullable
    public String getScope() {
        return Scope;
    }

    public void setAccessToken(@Nullable String accessToken) {
        AccessToken = accessToken;
    }

    @Nullable
    public String getTokenType() {
        return TokenType;
    }

    public void setTokenType(@Nullable String tokenType) {
        TokenType = tokenType;
    }

    public void setScope(@Nullable String scope) {
        Scope = scope;
    }

    public int getExpiresIn() {
        return ExpiresIn;
    }

    public void setExpiresIn(int expiresIn) {
        ExpiresIn = expiresIn;
    }
}