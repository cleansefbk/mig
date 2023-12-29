package it.oidc.helper;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import it.oidc.exception.OIDCException;
import it.oidc.util.JSONUtil;

public class OAuth2Helper {

	public static final String JWT_BARRIER = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

	private static final Logger logger = LoggerFactory.getLogger(OAuth2Helper.class);

	private final JWTHelper jwtHelper;

	private static final String REFRESH_TOKEN = "refresh_token";
	private static final String ACCESS_TOKEN = "access_token";

	public static final String AUTHORIZATION_CODE = "authorization_code";
	public static final String CLIENT_CREDENTIALS = "client_credentials";

	public OAuth2Helper(JWTHelper jwtHelper) {
		this.jwtHelper = jwtHelper;
	}

	/**
	 * Obtain the Access Token from the Authorization Code
	 *
	 * @see <a href="https://tools.ietf.org/html/rfc6749#section-4.1.3">
	 * https://tools.ietf.org/html/rfc6749#section-4.1.3</a>
	 *
	 * @param redirectUrl
	 * @param state
	 * @param code
	 * @param issuerId
	 * @param clientConf the "well known" configuration of the federation entity making
	 * the request
	 * @param tokenEndpointUrl
	 * @param codeVerifier
	 * @return
	 * @throws Exception
	 */

	// funzione funzionante ma senza campi client_assertion e client_assertion_type
	public JSONObject performAccessTokenRequest(
			String redirectUrl, String state, String code,
			String clientId, String tokenEndpointUrl, String codeVerifier)
		throws OIDCException {
		try {
			
			// Body Parameters

			Map<String, Object> params = new HashMap<>();

			params.put("grant_type", AUTHORIZATION_CODE);
			params.put("client_id", clientId);
			params.put("code_verifier", codeVerifier);
			params.put("code", code);
			params.put("redirect_uri", redirectUrl);

			logger.debug("#### params "+buildPostBody(params));

			// POST

			HttpRequest request = HttpRequest.newBuilder()
				.uri(new URI(tokenEndpointUrl))
				.POST(HttpRequest.BodyPublishers.ofString(buildPostBody(params)))
				.header("Content-Type", "application/x-www-form-urlencoded")
				.build();

			// TODO: timeout from options?
			HttpResponse<String> response = HttpClient.newBuilder()
				.build()
				.send(request, BodyHandlers.ofString());
			if (response.statusCode() != 200) {
				logger.error(
					"Something went wrong with {}: {}", state, response.statusCode());
			}
			else {
				try {
					return new JSONObject(response.body());
				}
				catch(Exception e) {
					logger.error(
						"Something went wrong with {}: {}", state, e.getMessage());
				}
			}

			return new JSONObject();
		}
		catch (Exception e) {
			throw new OIDCException(e);
		}
	}

	// Prova di inserimento campi client_assertion e client_assertion_type
	public JSONObject performAccessTokenRequest2(
			String redirectUrl, String state, String code,
			String clientId, String tokenEndpointUrl, String codeVerifier)
			throws OIDCException {

		// Stampe di debug

		JSONObject payloadtry = new JSONObject()
				.put("iss", clientId)
				.put("sub", clientId)
				.put("aud", JSONUtil.asJSONArray(tokenEndpointUrl))
				.put("iat", JWTHelper.getIssuedAt())
				.put("exp", JWTHelper.getExpiresOn())
				.put("jti", UUID.randomUUID().toString());

		logger.debug("payolad: " + payloadtry);

		String clientAssertiontry = jwtHelper.createPlainJWS(payloadtry);

		logger.debug("clientAssertion: " + clientAssertiontry);

		logger.debug("JWT_BARRIER (client_assertion_try): " + JWT_BARRIER);

		try {

			// client_assertion

			JSONObject payload = new JSONObject()
					.put("iss", clientId)
					.put("sub", clientId)
					.put("aud", JSONUtil.asJSONArray(tokenEndpointUrl))
					.put("iat", JWTHelper.getIssuedAt())
					.put("exp", JWTHelper.getExpiresOn())
					.put("jti", UUID.randomUUID().toString());

			String clientAssertion = jwtHelper.createPlainJWS(payload);

			// Body Parameters

			Map<String, Object> params = new HashMap<>();

			params.put("grant_type", AUTHORIZATION_CODE);
			params.put("client_id", clientId);
			params.put("code_verifier", codeVerifier);
			params.put("code", code);
			params.put("redirect_uri", redirectUrl);

			params.put("client_assertion", clientAssertion);
			params.put("client_assertion_type", JWT_BARRIER);


			logger.debug("#### params "+buildPostBody(params));

			// POST

			HttpRequest request = HttpRequest.newBuilder()
					.uri(new URI(tokenEndpointUrl))
					.POST(HttpRequest.BodyPublishers.ofString(buildPostBody(params)))
					.header("Content-Type", "application/x-www-form-urlencoded")
					.build();

			// TODO: timeout from options?
			HttpResponse<String> response = HttpClient.newBuilder()
					.build()
					.send(request, BodyHandlers.ofString());
			if (response.statusCode() != 200) {
				logger.error(
						"Something went wrong with {}: {}", state, response.statusCode());
			}
			else {
				try {
					return new JSONObject(response.body());
				}
				catch(Exception e) {
					logger.error(
							"Something went wrong with {}: {}", state, e.getMessage());
				}
			}

			return new JSONObject();
		}
		catch (Exception e) {
			throw new OIDCException(e);
		}
	}
	
	public String sendRevocationRequest(
			String token, String clientId, String revocationUrl, String clientSecret, String scope)
		throws OIDCException {

		try {
			// Body Parameters

			Map<String, Object> params = new HashMap<>();

			params.put("grant_type", CLIENT_CREDENTIALS);
			params.put("client_id", clientId);
			params.put("client_secret", clientSecret);
			params.put("scope", scope);

			params.put("token", token);
			//params.put("client_assertion", clientAssertion);
			params.put("client_assertion_type", JWT_BARRIER);

			if (logger.isDebugEnabled()) {
				logger.debug("Send Token Revocation: {}", buildPostBody(params));
			}

			// POST

			HttpRequest request = HttpRequest.newBuilder()
				.uri(new URI(revocationUrl))
				.POST(HttpRequest.BodyPublishers.ofString(buildPostBody(params)))
				.header("Content-Type", "application/x-www-form-urlencoded")
				.build();

			//TODO timeout from options
			HttpResponse<String> response = HttpClient.newBuilder()
				.build()
				.send(request, BodyHandlers.ofString());

			logger.debug("#### response "+response + " - " + response.body());

			if (response.statusCode() != 200) {
				logger.error(
					"Token revocation failed: {}", response.statusCode());
			}

			return ("response " + response + " - " + response.body());
		}
		catch (Exception e) {
			throw new OIDCException(e);
		}
	}

	public String sendIntrospectionRequest(
			String token, String clientId, String revocationUrl, String clientSecret, String scope)
			throws OIDCException {

		try {
			// Body Parameters

			Map<String, Object> params = new HashMap<>();

			params.put("grant_type", CLIENT_CREDENTIALS);
			params.put("client_id", clientId);
			params.put("client_secret", clientSecret);
			params.put("scope", scope);

			params.put("token", token);
			params.put("token_type_hint", ACCESS_TOKEN);

			//params.put("client_assertion", clientAssertion);
			params.put("client_assertion_type", JWT_BARRIER);

			if (logger.isDebugEnabled()) {
				logger.debug("Send Token Revocation: {}", buildPostBody(params));
			}

			// POST

			HttpRequest request = HttpRequest.newBuilder()
					.uri(new URI(revocationUrl))
					.POST(HttpRequest.BodyPublishers.ofString(buildPostBody(params)))
					.header("Content-Type", "application/x-www-form-urlencoded")
					.build();



			//TODO timeout from options
			HttpResponse<String> response = HttpClient.newBuilder()
					.build()
					.send(request, BodyHandlers.ofString());

			logger.debug("#### response "+response + " - " + response.body());

			if (response.statusCode() != 200) {
				logger.error(
						"Token revocation failed: {}", response.statusCode());
			}

			return ("response " + response + " - " + response.body());
		}
		catch (Exception e) {
			throw new OIDCException(e);
		}
	}

	private static String buildPostBody(Map<String, Object> params) {
		if (params == null || params.isEmpty()) {
			return "";
		}

		boolean first = true;

		StringBuilder sb = new StringBuilder(params.size() * 3);

		for (Map.Entry<String, Object> param : params.entrySet()) {
			if (first) {
				first = false;
			}
			else {
				sb.append("&");
			}

			sb.append(
				URLEncoder.encode(param.getKey().toString(), StandardCharsets.UTF_8));
			sb.append("=");

			if (param.getValue() != null) {
				sb.append(
					URLEncoder.encode(
						param.getValue().toString(), StandardCharsets.UTF_8));
			}
		}

		return sb.toString();
	}

}
