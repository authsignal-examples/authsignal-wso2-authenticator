package com.authsignal.wso2.authenticator.internal;

import com.authsignal.wso2.authenticator.AuthsignalPasskeyAuthenticator;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;
import org.wso2.carbon.user.core.service.RealmService;

public final class AuthsignalPasskeyAuthenticatorServiceComponent {

    private static final Log LOG = LogFactory.getLog(AuthsignalPasskeyAuthenticatorServiceComponent.class);
    private static RealmService realmService;

    protected void activate(ComponentContext context) {
        context.getBundleContext().registerService(
                ApplicationAuthenticator.class.getName(), new AuthsignalPasskeyAuthenticator(), null);
        LOG.info("Authsignal passkey authenticator bundle activated");
    }

    public static RealmService getRealmService() {
        return realmService;
    }

    protected void setRealmService(RealmService service) {
        realmService = service;
    }

    protected void unsetRealmService(RealmService service) {
        if (realmService == service) {
            realmService = null;
        }
    }
}

