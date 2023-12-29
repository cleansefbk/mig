package it.oidc.callback;

import it.oidc.model.AuthnRequest;
import it.oidc.model.AuthnToken;

public interface RelyingPartyLogoutCallback {

	public void logout(String userKey, AuthnRequest authnRequest, AuthnToken authnToken);

}
