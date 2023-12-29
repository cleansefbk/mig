package it.oidc.spring.boot.relying.party.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;


@Configuration
@ConfigurationProperties(prefix = "client-credentials")
public class ClientConfig {

    String scopes;

    String client_secret;

    String client_id;
    
    String code_challenge;

    public String getScopes() {
        return scopes;
    }

    public void setScopes(String scopes) {
        this.scopes = scopes;
    }

    public String getClientSecret() {
        return client_secret;
    }

    public void setClientSecret(String client_secret) {
        this.client_secret = client_secret;
    }

	public String getClient_secret() {
		return client_secret;
	}

	public void setClient_secret(String client_secret) {
		this.client_secret = client_secret;
	}

	public String getClient_id() {
		return client_id;
	}

	public void setClient_id(String client_id) {
		this.client_id = client_id;
	}

	public String getCode_challenge() {
		return code_challenge;
	}

	public void setCode_challenge(String code_challenge) {
		this.code_challenge = code_challenge;
	}



}
