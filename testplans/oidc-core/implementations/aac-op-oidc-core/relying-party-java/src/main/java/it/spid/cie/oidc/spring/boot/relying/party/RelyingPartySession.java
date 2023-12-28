package it.spid.cie.oidc.spring.boot.relying.party;

import it.spid.cie.oidc.spring.boot.relying.party.config.ClientConfig;

public class RelyingPartySession {

	public enum Status {
		LOGOUT,
		LOGGED,
	}
	
	Status status = Status.LOGOUT;
	String user;
	String code;
	String state;
	String idToken;
	String refreshToken;
	String accessToken;
	
	EndPointConfiguration configuration;

	ClientConfig clientConfig;
	
	public Status getStatus() {
		return status;
	}
	public void setStatus(Status status) {
		this.status = status;
	}
	public String getUser() {
		return user;
	}
	public void setUser(String user) {
		this.user = user;
	}
	public String getCode() {
		return code;
	}
	public void setCode(String code) {
		this.code = code;
	}
	public String getIdToken() {
		return idToken;
	}
	public void setIdToken(String idToken) {
		this.idToken = idToken;
	}
	public String getRefreshToken() {
		return refreshToken;
	}
	public void setRefreshToken(String refreshToken) {
		this.refreshToken = refreshToken;
	}
	public String getState() {
		return state;
	}
	public void setState(String state) {
		this.state = state;
	}
	public void setAccessToken(String accessToken) {
		this.accessToken = accessToken;
	}
	public String getAccessToken() {
		return accessToken;
	}
	public EndPointConfiguration getConfiguration() {
		return configuration;
	}
	public void setConfiguration(EndPointConfiguration configuration) {
		this.configuration = configuration;
	}

	public ClientConfig getClientConfig() {
		return clientConfig;
	}
	public void setClientConfig(ClientConfig clientConfig) {
		this.clientConfig = clientConfig;
	}

}
