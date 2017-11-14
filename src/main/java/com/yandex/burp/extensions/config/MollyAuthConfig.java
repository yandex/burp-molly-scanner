package com.yandex.burp.extensions.config;

import com.google.gson.annotations.SerializedName;

/**
 * Created by ezaitov on 09.02.2017.
 */
public class MollyAuthConfig {
    @SerializedName("auth_username")
    private String authUsername;

    @SerializedName("auth_password")
    private String authPassword;

    @SerializedName("auth_host")
    private String authHost;

    @SerializedName("auth_schema")
    private String authSchema;

    @SerializedName("auth_provider")
    private String authProvider;

    public String getAuthHost() {
        return authHost;
    }

    public String getAuthUsername() {
        return authUsername;
    }

    public String getAuthSchema() {
        return authSchema;
    }

    public String getAuthPassword() {
        return authPassword;
    }

    public void setAuthHost(String authHost) {
        this.authHost = authHost;
    }

    public void setAuthPassword(String authPassword) {
        this.authPassword = authPassword;
    }

    public void setAuthUsername(String authUsername) {
        this.authUsername = authUsername;
    }

    public void setAuthSchema(String authSchema) {
        this.authSchema = authSchema;
    }

    public String getAuthProvider() { return authProvider; }

    public void setAuthProvider(String authProvider) { this.authProvider = authProvider; }
}
