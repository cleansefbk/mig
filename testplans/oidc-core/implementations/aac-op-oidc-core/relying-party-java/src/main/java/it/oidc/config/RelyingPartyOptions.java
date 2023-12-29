package it.oidc.config;

import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import it.oidc.util.Validator;

public class RelyingPartyOptions extends GlobalOptions<RelyingPartyOptions> {

	public static final String[] SUPPORTED_APPLICATION_TYPES = new String[] { "web" };

	public static final String[] SUPPORTED_RESPONSE_TYPES = new String[] { "code" };

	private String applicationName;
	private String applicationType = "web";
	private Set<String> contacts = new HashSet<>();
	private String clientId;
	private Set<String> redirectUris = new HashSet<>();
	private String jwk;
	
	private String userKeyClaim;

	private String idTokenSignedResponseAlg;
	private String userinfoSignedResponseAlg;
	private String userinfoEncryptedResponseAlg;
	private String userinfoEncryptedResponseEnc;
	private String tokenEndpointAuthMethod;

	private String federationResolveEndpoint;
	private String organizationName;
	private String homepageUri;
	private String policyUri;
	private String logoUri;
	
	public String getApplicationName() {
		return applicationName;
	}

	public String getApplicationType() {
		return applicationType;
	}

	public Set<String> getContacts() {
		return Collections.unmodifiableSet(contacts);
	}

	public String getClientId() {
		return clientId;
	}

	public Set<String> getRedirectUris() {
		return Collections.unmodifiableSet(redirectUris);
	}

	public String getJwk() {
		return jwk;
	}

	public String getIdTokenSignedResponseAlg() {
		return idTokenSignedResponseAlg;
	}
	public String getUserinfoSignedResponseAlg() {
		return userinfoSignedResponseAlg;
	}
	public String getUserinfoEncryptedResponseAlg() {
		return userinfoEncryptedResponseAlg;
	}
	public String getUserinfoEncryptedResponseEnc() {
		return userinfoEncryptedResponseEnc;
	}
	public String getTokenEndpointAuthMethod() {
		return tokenEndpointAuthMethod;
	}

	public String getFederationResolveEndpoint() { return federationResolveEndpoint; }

	public String getOrganizationName() { return organizationName; }

	public String getHomepageUri() { return homepageUri; }

	public String getPolicyUri() { return policyUri; }

	public String getLogoUri() { return logoUri; }

	public String getUserKeyClaim() {
		return userKeyClaim;
	}

	public RelyingPartyOptions setApplicationName(String applicationName) {
		if (!Validator.isNullOrEmpty(applicationName)) {
			this.applicationName = applicationName;
		}

		return this;
	}

	public RelyingPartyOptions setClientId(String clientId) {
		if (!Validator.isNullOrEmpty(clientId)) {
			this.clientId = clientId;
		}

		return this;
	}

	public RelyingPartyOptions setIdTokenSignedResponseAlg(String idTokenSignedResponseAlg) {
		if (!Validator.isNullOrEmpty(idTokenSignedResponseAlg)) {
			this.idTokenSignedResponseAlg = idTokenSignedResponseAlg;
		}

		return this;
	}

	public RelyingPartyOptions setUserinfoSignedResponseAlg(String userinfoSignedResponseAlg) {
		if (!Validator.isNullOrEmpty(userinfoSignedResponseAlg)) {
			this.userinfoSignedResponseAlg = userinfoSignedResponseAlg;
		}

		return this;
	}
	public RelyingPartyOptions setUserinfoEncryptedResponseAlg(String userinfoEncryptedResponseAlg) {
		if (!Validator.isNullOrEmpty(userinfoEncryptedResponseAlg)) {
			this.userinfoEncryptedResponseAlg = userinfoEncryptedResponseAlg;
		}

		return this;
	}
	public RelyingPartyOptions setUserinfoEncryptedResponseEnc(String userinfoEncryptedResponseEnc) {
		if (!Validator.isNullOrEmpty(userinfoEncryptedResponseEnc)) {
			this.userinfoEncryptedResponseEnc = userinfoEncryptedResponseEnc;
		}

		return this;
	}
	public RelyingPartyOptions setTokenEndpointAuthMethod(String tokenEndpointAuthMethod) {
		if (!Validator.isNullOrEmpty(tokenEndpointAuthMethod)) {
			this.tokenEndpointAuthMethod = tokenEndpointAuthMethod;
		}

		return this;
	}

	public RelyingPartyOptions setFederationResolveEndpoint(String federationResolveEndpoint) {
		if (!Validator.isNullOrEmpty(federationResolveEndpoint)) {
			this.federationResolveEndpoint = federationResolveEndpoint;
		}

		return this;
	}
	public RelyingPartyOptions setOrganizationName(String organizationName) {
		if (!Validator.isNullOrEmpty(organizationName)) {
			this.organizationName = organizationName;
		}

		return this;
	}
	public RelyingPartyOptions setHomepageUri(String homepageUri) {
		if (!Validator.isNullOrEmpty(homepageUri)) {
			this.homepageUri = homepageUri;
		}

		return this;
	}
	public RelyingPartyOptions setPolicyUri(String policyUri) {
		if (!Validator.isNullOrEmpty(policyUri)) {
			this.policyUri = policyUri;
		}

		return this;
	}
	public RelyingPartyOptions setLogoUri(String logoUri) {
		if (!Validator.isNullOrEmpty(logoUri)) {
			this.logoUri = logoUri;
		}

		return this;
	}
	public RelyingPartyOptions setContacts(Collection<String> contacts) {
		if (contacts != null && !contacts.isEmpty()) {
			this.contacts.clear();
			this.contacts.addAll(contacts);
		}

		return this;
	}

	public RelyingPartyOptions setJWK(String jwk) {
		if (!Validator.isNullOrEmpty(jwk)) {
			this.jwk = jwk;
		}

		return this;
	}

	public RelyingPartyOptions setRedirectUris(Collection<String> redirectUris) {
		if (redirectUris != null && !redirectUris.isEmpty()) {
			this.redirectUris.clear();
			this.redirectUris.addAll(redirectUris);
		}

		return this;
	}

	
}
