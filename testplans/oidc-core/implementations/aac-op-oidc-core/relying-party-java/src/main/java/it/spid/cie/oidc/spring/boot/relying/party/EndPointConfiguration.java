package it.spid.cie.oidc.spring.boot.relying.party;


import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties(prefix = "endpoints")
public class EndPointConfiguration {

	String authzEndpoint;
	
	String tokenEndpoint;
	
	String userEndpoint;

	String logoutEndpoint;

	String revokeEndpoint;

	String introspectEndpoint;

	String codeVerifier;
	
	String codeChallenge;
	
	String redirectEndpoint;
	
	public String getAuthzEndpoint() {
		return authzEndpoint;
	}

	public void setAuthzEndpoint(String authzEndpoint) {
		this.authzEndpoint = authzEndpoint;
	}

	public String getTokenEndpoint() {
		return tokenEndpoint;
	}

	public void setTokenEndpoint(String tokenEndpoint) {
		this.tokenEndpoint = tokenEndpoint;
	}

	public String getUserEndpoint() {
		return userEndpoint;
	}

	public void setUserEndpoint(String userEndpoint) {
		this.userEndpoint = userEndpoint;
	}

	public String getCodeVerifier() {
		return codeVerifier;
	}

	public void setCodeVerifier(String codeVerifier) {
		this.codeVerifier = codeVerifier;
	}

	public String getCodeChallenge() {
		return codeChallenge;
	}

	public void setCodeChallenge(String codeChallenge) {
		this.codeChallenge = codeChallenge;
	}

	public String getLogoutEndpoint() {
		return logoutEndpoint;
	}

	public void setLogoutEndpoint(String logoutEndpoint) {
		this.logoutEndpoint = logoutEndpoint;
	}
	
	public String getRevokeEndpoint() {
		return revokeEndpoint;
	}
	
	public void setRevokeEndpoint(String revokeEndpoint) {
		this.revokeEndpoint = revokeEndpoint;
	}

	public String getIntrospectEndpoint() {
		return introspectEndpoint;
	}

	public void setIntrospectEndpoint(String introspectEndpoint) {
		this.introspectEndpoint = introspectEndpoint;
	}

	public String getRedirectEndpoint() {
		return redirectEndpoint;
	}

	public void setRedirectEndpoint(String redirectEndpoint) {
		this.redirectEndpoint = redirectEndpoint;
	}
}
