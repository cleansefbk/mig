package it.spid.cie.oidc.handler;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.ZoneOffset;

import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import it.spid.cie.oidc.config.OIDCConstants;
import it.spid.cie.oidc.config.RelyingPartyOptions;
import it.spid.cie.oidc.exception.OIDCException;
import it.spid.cie.oidc.exception.RelyingPartyException;
import it.spid.cie.oidc.exception.SchemaException;
import it.spid.cie.oidc.helper.JWTHelper;
import it.spid.cie.oidc.helper.OAuth2Helper;
import it.spid.cie.oidc.helper.OIDCHelper;
import it.spid.cie.oidc.helper.PKCEHelper;
import it.spid.cie.oidc.schemas.CIEClaimItem;
import it.spid.cie.oidc.schemas.ClaimItem;
import it.spid.cie.oidc.schemas.OIDCProfile;
import it.spid.cie.oidc.schemas.SPIDClaimItem;
import it.spid.cie.oidc.spring.boot.relying.party.AuthorizeRequest;
import it.spid.cie.oidc.spring.boot.relying.party.RelyingPartySession;
import it.spid.cie.oidc.util.JSONUtil;
import it.spid.cie.oidc.util.Validator;

public class RelyingPartyHandler {

	public RelyingPartyHandler(
			RelyingPartyOptions options)
		throws OIDCException {

		//options.validate();

		this.options = options;
		this.jwtHelper = new JWTHelper(options);
		this.oauth2Helper = new OAuth2Helper(this.jwtHelper);
		this.oidcHelper = new OIDCHelper(this.jwtHelper);
	}
	
	/**
	 * Build the "authorize url"
	 * 
	 * @param authorizeRequest
	 * @return
	 * @throws OIDCException
	 */
	public String getAuthorizeURL(AuthorizeRequest authorizeRequest, RelyingPartySession session)
			throws OIDCException {
		String authzEndpoint = authorizeRequest.getAuthzEndpoint();
		long issuedAt = LocalDateTime.now().toEpochSecond(ZoneOffset.UTC);
		String[] aud = new String[] { authzEndpoint };
		JSONObject claims = new JSONObject();
		JSONObject pkce = PKCEHelper.getPKCE();

		JSONObject authzData = new JSONObject()
			.put("scope", authorizeRequest.getScopes())
			.put("redirect_uri", authorizeRequest.getRedirect_uri())
			.put("response_type", authorizeRequest.getResponse_type())
			.put("nonce", authorizeRequest.getNonce())
			.put("state", authorizeRequest.getState())
			.put("client_id", authorizeRequest.getClient_id())
			.put("endpoint", authzEndpoint)
			.put("acr_values", authorizeRequest.getAcr_values())
			.put("iat", issuedAt)
			.put("aud", JSONUtil.asJSONArray(aud))
			.put("claims", claims)
			.put("prompt", authorizeRequest.getPrompt())
//			.put("code_verifier", pkce.getString("code_verifier"))
//			.put("code_challenge", pkce.getString("code_challenge"))
			.put("code_verifier", session.getConfiguration().getCodeVerifier())
			.put("code_challenge", session.getConfiguration().getCodeChallenge())
			.put("code_challenge_method", pkce.getString("code_challenge_method"));

		//authzData.remove("code_verifier");
		authzData.put("iss", authorizeRequest.getIss());
		authzData.put("sub", authorizeRequest.getClient_id());

		String requestObj = jwtHelper.createPlainJWS(authzData);

		if(authorizeRequest.addRequest())
			authzData.put("request", requestObj);

		String url = buildURL(authzEndpoint, authzData);

		logger.info("Starting Authn request to {}", url);

		return url;
	}

	public JSONObject getUserInfo(RelyingPartySession session)
		throws OIDCException {

			try {
				return doGetUserInfo(session);
			}
			catch (OIDCException e) {
				throw e;
			}
			catch (Exception e) {
				throw new RelyingPartyException.Generic(e);
			}
	}

	public JSONObject getToken(RelyingPartySession session)
			throws OIDCException {

			try {
				return doGetToken(session);
			}
			catch (OIDCException e) {
				throw e;
			}
			catch (Exception e) {
				throw new RelyingPartyException.Generic(e);
			}
	}

	protected JSONObject doGetUserInfo(RelyingPartySession session)
			throws OIDCException {

		JSONObject userInfo = oidcHelper.getPlainUserInfo(
				session.getState(), session.getAccessToken(), session.getConfiguration().getUserEndpoint());

		return userInfo;
	}

	protected JSONObject doGetToken(RelyingPartySession session)
			throws OIDCException {
		String codeVerifier = session.getConfiguration().getCodeVerifier();
		String code = session.getCode();
			if (Validator.isNullOrEmpty(code) || Validator.isNullOrEmpty(codeVerifier)) {
				throw new SchemaException.Validation(
					"Token response object validation failed");
			}

			//Scommentare per provare la funzione con campi client_assertion_type e assertion_type
			//JSONObject jsonTokenResponse = oauth2Helper.performAccessTokenRequest2(
			JSONObject jsonTokenResponse = oauth2Helper.performAccessTokenRequest(
					session.getConfiguration().getRedirectEndpoint(), session.getState(), code,
					session.getClientConfig().getClient_id(),
					session.getConfiguration().getTokenEndpoint(),
					session.getConfiguration().getCodeVerifier());
			
			return jsonTokenResponse;
		}

	public void revoke(RelyingPartySession session)
			throws OIDCException {

			try {
				doRevokeToken(session);
			}
			catch (OIDCException e) {
				throw e;
			}
			catch (Exception e) {
				throw new RelyingPartyException.Generic(e);
			}
	}

	public void introspect(RelyingPartySession session)
			throws OIDCException {

		try {
			doIntrospectToken(session);
		}
		catch (OIDCException e) {
			throw e;
		}
		catch (Exception e) {
			throw new RelyingPartyException.Generic(e);
		}
	}

	private void doRevokeToken(RelyingPartySession session) throws Exception {

		try {
			oauth2Helper.sendRevocationRequest(
					session.getAccessToken(), session.getClientConfig().getClient_id(), session.getConfiguration().getRevokeEndpoint(), session.getClientConfig().getClientSecret(), session.getClientConfig().getScopes());
		}
		catch (Exception e) {
			logger.error("Token revocation failed: {}", e.getMessage());
		}
	}

	private void doIntrospectToken(RelyingPartySession session) throws Exception {

		try {
			oauth2Helper.sendIntrospectionRequest(
					session.getAccessToken(), session.getClientConfig().getClient_id(), session.getConfiguration().getIntrospectEndpoint(), session.getClientConfig().getClientSecret(), session.getClientConfig().getScopes());
		}
		catch (Exception e) {
			logger.error("Token revocation failed: {}", e.getMessage());
		}
	}

//	protected String doPerformLogout(
//			String userKey, RelyingPartyLogoutCallback callback)
//		throws Exception {
//
//		if (Validator.isNullOrEmpty(userKey)) {
//			throw new RelyingPartyException.Generic("UserKey null or empty");
//		}
//
//		List<AuthnToken> authnTokens = persistence.findAuthnTokens(userKey);
//
//		if (authnTokens.isEmpty()) {
//			return options.getLogoutRedirectURL();
//		}
//
//		AuthnToken authnToken = ListUtil.getLast(authnTokens);
//
//		AuthnRequest authnRequest = persistence.fetchAuthnRequest(
//			authnToken.getAuthnRequestId());
//
//		if (authnRequest == null) {
//			throw new RelyingPartyException.Generic(
//				"No AuthnRequest with id " + authnToken.getAuthnRequestId());
//		}
//
//		JSONObject providerConfiguration = new JSONObject(
//			authnRequest.getProviderConfiguration());
//
//		String revocationUrl = providerConfiguration.optString("revocation_endpoint");
//
//		// Do local logout
//
//		if (callback != null) {
//			callback.logout(userKey, authnRequest, authnToken);
//		}
//
//		if (Validator.isNullOrEmpty(revocationUrl)) {
//			logger.warn(
//				"{} doesn't expose the token revocation endpoint.",
//				authnRequest.getProviderId());
//
//			return options.getLogoutRedirectURL();
//		}
//
//		FederationEntity entityConf = persistence.fetchFederationEntity(
//			authnRequest.getClientId(), true);
//
//		JWTHelper.getJWKSetFromJSON(entityConf.getJwks());
//
//		authnToken.setRevoked(LocalDateTime.now());
//
//		authnToken = persistence.storeOIDCAuthnToken(authnToken);
//
//		try {
//			oauth2Helper.sendRevocationRequest(
//				authnToken.getAccessToken(), authnRequest.getClientId(), revocationUrl,
//				entityConf);
//		}
//		catch (Exception e) {
//			logger.error("Token revocation failed: {}", e.getMessage());
//		}
//
//		// Revoke older user's authnToken. Evaluate better
//
//		authnTokens = persistence.findAuthnTokens(userKey);
//
//		for (AuthnToken oldToken : authnTokens) {
//			oldToken.setRevoked(authnToken.getRevoked());
//
//			persistence.storeOIDCAuthnToken(oldToken);
//		}
//
//		return options.getLogoutRedirectURL();
//	}

	

	// TODO: move to an helper?
	private String buildURL(String endpoint, JSONObject params) {
		StringBuilder sb = new StringBuilder();

		sb.append(endpoint);

		if (!params.isEmpty()) {
			boolean first = true;

			for (String key : params.keySet()) {
				if (first) {
					sb.append("?");
					first = false;
				}
				else {
					sb.append("&");
				}

				sb.append(key);
				sb.append("=");

				String value = params.get(key).toString();

				sb.append(URLEncoder.encode(value, StandardCharsets.UTF_8));
			}
		}

		return sb.toString();
	}

	private JSONObject getRequestedClaims(OIDCProfile profile) {
		return options.getRequestedClaimsAsJSON(profile);
	}

	private String getSubjectFromWellKnownURL(String url) {
		int x = url.indexOf(OIDCConstants.OIDC_FEDERATION_WELLKNOWN_URL);

		if (x > 0) {
			return url.substring(0, x);
		}

		return "";
	}

	private String getUserKeyFromUserInfo(JSONObject userInfo) {
		String userKey = userInfo.optString(options.getUserKeyClaim(), null);

		if (userKey != null) {
			return userKey;
		}

		ClaimItem spidClaim = SPIDClaimItem.get(options.getUserKeyClaim());

		if (spidClaim != null) {
			userKey = userInfo.optString(spidClaim.getAlias(), null);

			if (userKey != null) {
				return userKey;
			}
		}
		else {
			spidClaim = SPIDClaimItem.getByAlias(options.getUserKeyClaim());

			if (spidClaim != null) {
				userKey = userInfo.optString(spidClaim.getName(), null);

				if (userKey != null) {
					return userKey;
				}
			}
		}

		ClaimItem cieClaim = CIEClaimItem.get(options.getUserKeyClaim());

		if (cieClaim != null) {
			userKey = userInfo.optString(cieClaim.getAlias(), null);

			if (userKey != null) {
				return userKey;
			}
		}
		else {
			cieClaim = CIEClaimItem.getByAlias(options.getUserKeyClaim());

			if (cieClaim != null) {
				userKey = userInfo.optString(cieClaim.getName());

				if (userKey != null) {
					return userKey;
				}
			}
		}

		return null;
	}

	private static final Logger logger = LoggerFactory.getLogger(
		RelyingPartyHandler.class);

	private final RelyingPartyOptions options;
	private final JWTHelper jwtHelper;
	private final OAuth2Helper oauth2Helper;
	private final OIDCHelper oidcHelper;

}
