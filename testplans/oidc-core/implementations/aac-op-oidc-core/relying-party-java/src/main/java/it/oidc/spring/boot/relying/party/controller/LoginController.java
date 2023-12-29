package it.oidc.spring.boot.relying.party.controller;

import java.io.InputStream;
import java.net.URI;
import java.net.URL;
import java.net.URLConnection;
import java.util.Map;
import java.util.Scanner;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import org.springframework.web.servlet.view.RedirectView;

import it.oidc.schemas.TokenResponse;
import it.oidc.spring.boot.relying.party.AuthorizeRequest;
import it.oidc.spring.boot.relying.party.RelyingPartySession;
import it.oidc.spring.boot.relying.party.RelyingPartyWrapper;
import it.oidc.util.Validator;

@RestController
public class LoginController {
	private static Logger logger = LoggerFactory.getLogger(LoginController.class);

	@GetMapping("/login")
	public ModelAndView home(HttpServletRequest request)
		throws Exception {

		ModelAndView mav = new ModelAndView("login");
		
		return mav;
	}

	@Autowired
	private RelyingPartyWrapper relyingPartyWrapper;

	@GetMapping("/oauth/authorize")
	public ResponseEntity<Void> authorize(HttpServletRequest request)
		throws Exception {

		if(RelyingPartySession.Status.LOGGED.equals(relyingPartyWrapper.getSession().getStatus())) {
			relyingPartyWrapper.getSession().setStatus(RelyingPartySession.Status.LOGOUT);
			return ResponseEntity
					.status(HttpStatus.FOUND)
					.location(URI.create(logoutUrl()))
					.build();
		}
			
		AuthorizeRequest authorizeRequest = new AuthorizeRequest();
		authorizeRequest.setScopes("openid profile email offline_access");
		//authorizeRequest.setCode_challenge(relyingPartyWrapper.getSession().getAuthorizeRequest().getCode_challenge());
		authorizeRequest.setCode_challenge("-uE-LdYx2fzfr9CuTZ9LO-Xe5ZkugIvlYQdrNT9kKXY");
		authorizeRequest.setCode_challenge_method("S256");
		
		authorizeRequest.setAlg("RS256");
		authorizeRequest.setKid("rsa1");
		
		authorizeRequest.setClient_id(relyingPartyWrapper.getSession().getClientConfig().getClient_id());
		authorizeRequest.setRedirect_uri(relyingPartyWrapper.getSession().getConfiguration().getRedirectEndpoint());
		authorizeRequest.setResponse_type("code");
		authorizeRequest.setResponse_mode("query");
//		authorizeRequest.setAcr_values(null);
//		authorizeRequest.setClaims(null);
//		authorizeRequest.setExp(null);
//		authorizeRequest.setIat(null);
		authorizeRequest.setIss(relyingPartyWrapper.getSession().getClientConfig().getClient_id());
		authorizeRequest.setAud(relyingPartyWrapper.getSession().getConfiguration().getRedirectEndpoint());
//		authorizeRequest.setUi_locales(null);
		
		//authorizeRequest.setJwks(relyingPartyWrapper.getJwk());
		authorizeRequest.setAuthzEndpoint(relyingPartyWrapper.getSession().getConfiguration().getAuthzEndpoint());
		
		authorizeRequest.setAddRequest(true);
		String authorizeURL = relyingPartyWrapper.getAuthorizeURL(authorizeRequest);
		
		//relyingPartyWrapper.getSession().setAuthorizeRequest(authorizeRequest);
		
		return ResponseEntity
			.status(HttpStatus.FOUND)
			.location(URI.create(authorizeURL))
			.build();
	}
	
	@GetMapping("/token")
	public RedirectView token(
			@RequestParam Map<String,String> params,
			final HttpServletRequest request, HttpServletResponse response)
		throws Exception {

		if(RelyingPartySession.Status.LOGGED.equals(relyingPartyWrapper.getSession().getStatus())) {
			JSONObject jsonTokenResponse = relyingPartyWrapper.getToken(relyingPartyWrapper.getSession());
			TokenResponse tokenResponse = TokenResponse.of(jsonTokenResponse);
			logger.debug("TokenResponse=" + tokenResponse.toString());
			relyingPartyWrapper.getSession().setIdToken(tokenResponse.getIdToken());
			relyingPartyWrapper.getSession().setAccessToken(tokenResponse.getAccessToken());
			
		}
		return new RedirectView("login");
	}
		
	@GetMapping("/userinfo")
	public RedirectView userinfo(
			@RequestParam Map<String,String> params,
			RedirectAttributes attributes,
			final HttpServletRequest request, HttpServletResponse response)
		throws Exception {

		if(RelyingPartySession.Status.LOGGED.equals(relyingPartyWrapper.getSession().getStatus())) {
			JSONObject userInfo = relyingPartyWrapper.getUserInfo(relyingPartyWrapper.getSession());
			logger.debug("userInfo=" + userInfo.toString());
			attributes.addFlashAttribute("userInfo", userInfo);
		}
		return new RedirectView("login");
	}

	@GetMapping("/revoke")
	public RedirectView revoke(
			@RequestParam Map<String,String> params,
			RedirectAttributes attributes,
			final HttpServletRequest request, HttpServletResponse response)
		throws Exception {

		if(RelyingPartySession.Status.LOGGED.equals(relyingPartyWrapper.getSession().getStatus())) {
			String result = relyingPartyWrapper.revoke(relyingPartyWrapper.getSession());
			attributes.addFlashAttribute("revoke", result);
		}
		return new RedirectView("login");
	}

	@GetMapping("/introspect")
	public RedirectView introspect(
			@RequestParam Map<String,String> params,
			RedirectAttributes attributes,
			final HttpServletRequest request, HttpServletResponse response)
			throws Exception {

		if(RelyingPartySession.Status.LOGGED.equals(relyingPartyWrapper.getSession().getStatus())) {
			String result = relyingPartyWrapper.introspect(relyingPartyWrapper.getSession());
			attributes.addFlashAttribute("introspect", result);
		}

		return new RedirectView("login");
	}

	@GetMapping("/signin-callback")
	public RedirectView callback(
			@RequestParam Map<String,String> params,
			RedirectAttributes attributes,
			HttpServletRequest request, HttpServletResponse response)
		throws Exception {
		logger.debug("### signin-callback");
		if (params.containsKey("error")) {
			String msg = new JSONObject(params).toString(2);

			logger.error(msg);

			throw new Exception(msg);
		}

		String state = params.get("state");
		String code = params.get("code");
		logger.debug("### code " + code);
		
		RedirectView redirectView = new RedirectView("login");
		
		if(code != null) {
			attributes.addFlashAttribute("code", code);
			
			relyingPartyWrapper.getSession().setCode(code);
			relyingPartyWrapper.getSession().setState(state);
			relyingPartyWrapper.getSession().setStatus(RelyingPartySession.Status.LOGGED);
			//JSONObject userInfo = relyingPartyWrapper.getUserInfo(relyingPartyWrapper.getSession());
			
			JSONObject jsonTokenResponse = relyingPartyWrapper.getToken(relyingPartyWrapper.getSession());
			TokenResponse tokenResponse = TokenResponse.of(jsonTokenResponse);
			logger.debug("TokenResponse=" + tokenResponse.toString());
			logger.debug("TokenResponse=" + tokenResponse.toString());
			relyingPartyWrapper.getSession().setIdToken(tokenResponse.getIdToken());
			relyingPartyWrapper.getSession().setAccessToken(tokenResponse.getAccessToken());
			attributes.addFlashAttribute("token", jsonTokenResponse);
			
			JSONObject userInfo = relyingPartyWrapper.getUserInfo(relyingPartyWrapper.getSession());
			attributes.addFlashAttribute("userInfo", userInfo);
		}
		return redirectView;
	}

	@GetMapping("/userlogout")
	public RedirectView logout(
			@RequestParam Map<String,String> params,
			final HttpServletRequest request, HttpServletResponse response)
		throws Exception {

		String logoutUrl = logoutUrl();
		if (!Validator.isNullOrEmpty(logoutUrl)) {
			RedirectView redirectView = new RedirectView(logoutUrl);
			relyingPartyWrapper.getSession().setStatus(RelyingPartySession.Status.LOGOUT);
			return redirectView;
		}

		return new RedirectView("login");
	}

	private String logoutUrl() {
		String redirectURL = relyingPartyWrapper.getSession().getConfiguration().getLogoutEndpoint();
		
		redirectURL += "?client_id="+ relyingPartyWrapper.getSession().getClientConfig().getClient_id() +"&post_logout_redirect_uri="+relyingPartyWrapper.getSession().getConfiguration().getRedirectEndpoint();
		return redirectURL;
	}
	
	public String getJwk(String sURL) throws Exception {
		URL url = new URL(sURL);
	    URLConnection request = url.openConnection();
	    request.connect();
	    // Convert to a JSON object to print data
	    InputStream inStream = request.getInputStream();
	    String json = streamToString(inStream); // input stream to string
	    return json;
	}
	
	private String streamToString(InputStream inputStream) {
	    String text = new Scanner(inputStream, "UTF-8").useDelimiter("\\Z").next();
	    return text;
	  }
}
