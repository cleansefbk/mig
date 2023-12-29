package it.oidc.spring.boot.relying.party;

import java.util.UUID;

public class AuthorizeRequest {
	String scopes;
	String code_challenge;
	String code_challenge_method;
	
	//JWT 
	//header
	String alg;
	String kid;
	//payload
	String client_id;
	String redirect_uri;
	String response_type;
	String state = UUID.randomUUID().toString();
	String response_mode;
	String nonce = UUID.randomUUID().toString();
	String prompt = "login";	
	String acr_values;
	String claims;
	String exp;
	String iat;
	String iss;
	String aud;
	String ui_locales;
	
	//metadata url
	String jwks;
	String authzEndpoint;
	
	private boolean addRequest = false;
	
	public String getScopes() {
		return scopes;
	}

	public void setScopes(String scopes) {
		this.scopes = scopes;
	}

	public String getCode_challenge() {
		return code_challenge;
	}

	public void setCode_challenge(String code_challenge) {
		this.code_challenge = code_challenge;
	}

	public String getCode_challenge_method() {
		return code_challenge_method;
	}

	public void setCode_challenge_method(String code_challenge_method) {
		this.code_challenge_method = code_challenge_method;
	}

	public String getAlg() {
		return alg;
	}

	public void setAlg(String alg) {
		this.alg = alg;
	}

	public String getKid() {
		return kid;
	}

	public void setKid(String kid) {
		this.kid = kid;
	}

	public String getClient_id() {
		return client_id;
	}

	public void setClient_id(String client_id) {
		this.client_id = client_id;
	}

	public String getRedirect_uri() {
		return redirect_uri;
	}

	public void setRedirect_uri(String redirect_uri) {
		this.redirect_uri = redirect_uri;
	}

	public String getResponse_type() {
		return response_type;
	}

	public void setResponse_type(String response_type) {
		this.response_type = response_type;
	}

	public String getState() {
		return state;
	}

	public void setState(String state) {
		this.state = state;
	}

	public String getResponse_mode() {
		return response_mode;
	}

	public void setResponse_mode(String response_mode) {
		this.response_mode = response_mode;
	}

	public String getNonce() {
		return nonce;
	}

	public void setNonce(String nonce) {
		this.nonce = nonce;
	}

	public String getPrompt() {
		return prompt;
	}

	public void setPrompt(String prompt) {
		this.prompt = prompt;
	}

	public String getAcr_values() {
		return acr_values;
	}

	public void setAcr_values(String acr_values) {
		this.acr_values = acr_values;
	}

	public String getClaims() {
		return claims;
	}

	public void setClaims(String claims) {
		this.claims = claims;
	}

	public String getExp() {
		return exp;
	}

	public void setExp(String exp) {
		this.exp = exp;
	}

	public String getIat() {
		return iat;
	}

	public void setIat(String iat) {
		this.iat = iat;
	}

	public String getIss() {
		return iss;
	}

	public void setIss(String iss) {
		this.iss = iss;
	}

	public String getAud() {
		return aud;
	}

	public void setAud(String aud) {
		this.aud = aud;
	}

	public String getUi_locales() {
		return ui_locales;
	}

	public void setUi_locales(String ui_locales) {
		this.ui_locales = ui_locales;
	}

	public String getJwks() {
		return jwks;
	}

	public void setJwks(String jwks) {
		this.jwks = jwks;
	}

	public String getAuthzEndpoint() {
		return authzEndpoint;
	}

	public void setAuthzEndpoint(String authzEndpoint) {
		this.authzEndpoint = authzEndpoint;
	}

	/**
	 * add request object as signed jwt into url
	 * @return
	 */
	public boolean addRequest() {
		return addRequest;
	}
	
	public void setAddRequest(boolean value) {
		this.addRequest = value;
	}
	
}
