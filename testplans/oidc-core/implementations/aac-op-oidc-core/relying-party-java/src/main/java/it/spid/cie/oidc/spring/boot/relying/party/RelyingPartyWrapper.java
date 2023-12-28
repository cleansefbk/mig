package it.spid.cie.oidc.spring.boot.relying.party;

import java.io.File;
import java.nio.file.Files;

import javax.annotation.PostConstruct;

import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import it.spid.cie.oidc.config.RelyingPartyOptions;
import it.spid.cie.oidc.exception.OIDCException;
import it.spid.cie.oidc.handler.RelyingPartyHandler;
import it.spid.cie.oidc.spring.boot.relying.party.config.ClientConfig;
import it.spid.cie.oidc.util.Validator;

@Component
public class RelyingPartyWrapper {

	public String getAuthorizeURL(AuthorizeRequest authorizeRequest)
			throws OIDCException {

		return relyingPartyHandler.getAuthorizeURL(authorizeRequest, relyingPartySession);
	}

	public JSONObject getToken(RelyingPartySession session)
			throws OIDCException {
		return relyingPartyHandler.getToken(session);
	}
	
	public JSONObject getUserInfo(RelyingPartySession session)
		throws OIDCException {

		return relyingPartyHandler.getUserInfo(session);
	}

	public void revoke(RelyingPartySession session)
			throws OIDCException {
		relyingPartyHandler.revoke(session);
	}

	public void introspect(RelyingPartySession session)
			throws OIDCException {
		relyingPartyHandler.introspect(session);
	}

	public String getUserKey(JSONObject userInfo) {
		String userKey = userInfo.optString("email");

		if (Validator.isNullOrEmpty(userKey)) {
			userKey = userInfo.optString("email", "");
		}

		return userKey;
	}

	public void reloadHandler() throws OIDCException {
		logger.info("reload handler");

		postConstruct();
	}

//	public String getJwk() {
//		String jwk = readFile(oidcConfig.getRelyingParty().getJwkFilePath());
//		return jwk;
//	}
	

	public RelyingPartySession getSession() {
		return relyingPartySession;
	}

	public void setSession(RelyingPartySession relyingPartySession) {
		this.relyingPartySession = relyingPartySession;
	}

	@PostConstruct
	private void postConstruct() throws OIDCException {
//		String jwk = readFile(oidcConfig.getRelyingParty().getJwkFilePath());
//		String trustMarks = readFile(
//			oidcConfig.getRelyingParty().getTrustMarksFilePath());
//
//		logger.info("final jwk: " + jwk);
//		logger.info("final trust_marks: " + trustMarks);

		RelyingPartyOptions options = new RelyingPartyOptions()
				
//				.setJWK(jwk)
//				.setTrustMarks(trustMarks)
				;

		relyingPartyHandler = new RelyingPartyHandler(options);
		relyingPartySession = new RelyingPartySession();
		relyingPartySession.setClientConfig(clientConfig);
		relyingPartySession.setConfiguration(configuration);
	}

	private String readFile(String filePath) {
		try {
			File file = new File(filePath);

			if (file.isFile() && file.canRead()) {
				return Files.readString(file.toPath());
			}
		}
		catch (Exception e) {
			logger.error(e.getMessage(), e);
		}

		return "";
	}

	private static Logger logger = LoggerFactory.getLogger(RelyingPartyWrapper.class);

	@Autowired
	EndPointConfiguration configuration;

	@Autowired
	ClientConfig clientConfig;

	private RelyingPartyHandler relyingPartyHandler;

	private RelyingPartySession relyingPartySession;


}
