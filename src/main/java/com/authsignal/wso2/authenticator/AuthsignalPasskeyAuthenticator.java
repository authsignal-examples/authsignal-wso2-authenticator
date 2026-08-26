package com.authsignal.wso2.authenticator;

import com.authsignal.wso2.authenticator.internal.AuthsignalPasskeyAuthenticatorServiceComponent;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.LocalApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.InvalidCredentialsException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * First-factor WSO2 authenticator backed by an Authsignal passkey challenge.
 *
 * The browser submits a short-lived Authsignal result token into the active
 * WSO2 commonauth transaction. This class validates it with Authsignal's
 * Server API before selecting the corresponding local WSO2 user.
 */
public final class AuthsignalPasskeyAuthenticator extends AbstractApplicationAuthenticator
        implements LocalApplicationAuthenticator {

    public static final String NAME = "AuthsignalPasskeyAuthenticator";
    public static final String FRIENDLY_NAME = "Authsignal Passkey";
    public static final String TOKEN_PARAMETER = "authsignalToken";
    public static final String DEFAULT_ACTION = "signInWithPasskeyAutofill";
    public static final String DEFAULT_BASE_URL = "https://api.authsignal.com/v1";

    private static final long serialVersionUID = 1L;
    private static final Log LOG = LogFactory.getLog(AuthsignalPasskeyAuthenticator.class);
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(10);
    private static final HttpClient HTTP_CLIENT = HttpClient.newBuilder()
            .connectTimeout(REQUEST_TIMEOUT)
            .build();

    @Override
    public boolean canHandle(HttpServletRequest request) {
        String token = request.getParameter(TOKEN_PARAMETER);
        return token != null && !token.trim().isEmpty();
    }

    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context)
            throws AuthenticationFailedException {
        String loginPage = ConfigurationFacade.getInstance().getAuthenticationEndpointURL();
        String passkeyPage = URI.create(loginPage).resolve("authsignal-passkey-login.html").toString();
        String query = FrameworkUtils.getQueryStringWithFrameworkContextId(
                context.getQueryParams(), context.getCallerSessionKey(), context.getContextIdentifier());

        try {
            response.sendRedirect(response.encodeRedirectURL(passkeyPage + "?" + query)
                    + "&authenticators=" + NAME + ":LOCAL");
        } catch (IOException error) {
            throw new AuthenticationFailedException("Could not open the Authsignal passkey login page", error);
        }
    }

    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context)
            throws AuthenticationFailedException {
        String token = request.getParameter(TOKEN_PARAMETER);
        if (token == null || token.trim().isEmpty()) {
            throw new InvalidCredentialsException("The Authsignal passkey result token is missing");
        }

        String secret = requiredSetting("AuthsignalSecret", "AUTHSIGNAL_SECRET");
        String baseUrl = setting("AuthsignalBaseUrl", "AUTHSIGNAL_API_URL", DEFAULT_BASE_URL);
        String action = setting("AuthsignalAction", "AUTHSIGNAL_ACTION", DEFAULT_ACTION);
        String userId = validateChallenge(baseUrl, secret, action, token);

        verifyLocalUserExists(context, userId);
        context.setSubject(AuthenticatedUser.createLocalAuthenticatedUserFromSubjectIdentifier(userId));
        LOG.info("Authsignal passkey authentication succeeded for the mapped WSO2 user");
    }

    private String validateChallenge(String baseUrl, String secret, String action, String token)
            throws AuthenticationFailedException {
        try {
            Map<String, String> payload = new LinkedHashMap<>();
            payload.put("token", token);
            payload.put("action", action);

            String credentials = Base64.getEncoder().encodeToString(
                    (secret + ":").getBytes(StandardCharsets.UTF_8));
            HttpRequest validationRequest = HttpRequest.newBuilder()
                    .uri(URI.create(stripTrailingSlash(baseUrl) + "/validate"))
                    .timeout(REQUEST_TIMEOUT)
                    .header("Authorization", "Basic " + credentials)
                    .header("Accept", "application/json")
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(JSONObject.toJSONString(payload)))
                    .build();

            HttpResponse<String> validationResponse = HTTP_CLIENT.send(
                    validationRequest, HttpResponse.BodyHandlers.ofString());
            if (validationResponse.statusCode() < 200 || validationResponse.statusCode() >= 300) {
                LOG.warn("Authsignal challenge validation returned HTTP " + validationResponse.statusCode());
                throw new InvalidCredentialsException("Authsignal rejected the passkey result");
            }

            JSONObject result = (JSONObject) new JSONParser().parse(validationResponse.body());
            boolean isValid = Boolean.TRUE.equals(result.get("isValid"));
            String state = stringValue(result.get("state"));
            String validatedAction = stringValue(result.get("actionCode"));
            String userId = stringValue(result.get("userId"));

            if (!isValid || !"CHALLENGE_SUCCEEDED".equals(state) || !action.equals(validatedAction)
                    || userId == null || userId.trim().isEmpty()) {
                throw new InvalidCredentialsException("The Authsignal passkey challenge was not successful");
            }
            return userId;
        } catch (InvalidCredentialsException error) {
            throw error;
        } catch (InterruptedException error) {
            Thread.currentThread().interrupt();
            throw new AuthenticationFailedException("Authsignal challenge validation was interrupted", error);
        } catch (Exception error) {
            LOG.error("Could not validate the Authsignal passkey challenge", error);
            throw new AuthenticationFailedException("Could not validate the Authsignal passkey challenge", error);
        }
    }

    private void verifyLocalUserExists(AuthenticationContext context, String username)
            throws AuthenticationFailedException {
        try {
            int tenantId = IdentityTenantUtil.getTenantId(context.getTenantDomain());
            UserRealm realm = AuthsignalPasskeyAuthenticatorServiceComponent.getRealmService()
                    .getTenantUserRealm(tenantId);
            if (realm == null) {
                throw new AuthenticationFailedException("The WSO2 tenant user realm could not be resolved",
                        User.getUserFromUserName(username));
            }

            UserStoreManager userStore = realm.getUserStoreManager();
            if (!userStore.isExistingUser(username)) {
                throw new InvalidCredentialsException("The Authsignal identity is not mapped to a local WSO2 user",
                        User.getUserFromUserName(username));
            }
        } catch (UserStoreException error) {
            throw new AuthenticationFailedException("Could not resolve the mapped WSO2 user",
                    User.getUserFromUserName(username), error);
        }
    }

    private String requiredSetting(String parameterName, String environmentName)
            throws AuthenticationFailedException {
        String value = setting(parameterName, environmentName, null);
        if (value == null || value.trim().isEmpty()) {
            throw new AuthenticationFailedException(environmentName + " is not configured");
        }
        return value;
    }

    private String setting(String parameterName, String environmentName, String defaultValue) {
        String environmentValue = System.getenv(environmentName);
        if (environmentValue != null && !environmentValue.trim().isEmpty()) {
            return environmentValue;
        }

        if (getAuthenticatorConfig() != null && getAuthenticatorConfig().getParameterMap() != null) {
            String configuredValue = getAuthenticatorConfig().getParameterMap().get(parameterName);
            if (configuredValue != null && !configuredValue.trim().isEmpty()) {
                return configuredValue;
            }
        }
        return defaultValue;
    }

    private static String stripTrailingSlash(String value) {
        return value.endsWith("/") ? value.substring(0, value.length() - 1) : value;
    }

    private static String stringValue(Object value) {
        return value instanceof String ? (String) value : null;
    }

    @Override
    protected boolean retryAuthenticationEnabled(AuthenticationContext context) {
        return true;
    }

    @Override
    public String getContextIdentifier(HttpServletRequest request) {
        return request.getParameter("sessionDataKey");
    }

    @Override
    public String getName() {
        return NAME;
    }

    @Override
    public String getFriendlyName() {
        return FRIENDLY_NAME;
    }
}

