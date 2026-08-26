# Authsignal authenticator for WSO2 Identity Server

This integration lets a self-hosted WSO2 Identity Server authenticate a local user with an Authsignal passkey. It contains two pieces:

1. An OSGi authenticator JAR that validates the Authsignal result token on the server.
2. A browser-side login-page integration that enables passkey conditional UI on WSO2's username field.

The current implementation has been tested with WSO2 Identity Server 7.2.0 and Java 11.

## Build

```shell
mvn clean verify
```

The installable bundle is created at:

```text
target/authsignal-wso2-authenticator-0.1.0-SNAPSHOT.jar
```

GitHub Actions also builds the bundle for every pull request and push to `main`. Download it from the workflow run's **Artifacts** section. Pushing a `v*` tag creates a GitHub release containing the JAR.

## Install the authenticator

1. Copy the JAR into WSO2:

   ```text
   <WSO2_HOME>/repository/components/dropins/
   ```

2. Add the contents of [`deployment.toml.example`](deployment.toml.example) to:

   ```text
   <WSO2_HOME>/repository/conf/deployment.toml
   ```

3. Provide the server-side Authsignal settings to the WSO2 process. Only `AUTHSIGNAL_SECRET` is required when using the default API URL and action:

   ```shell
   export AUTHSIGNAL_SECRET="YOUR_SECRET_KEY"
   export AUTHSIGNAL_API_URL="https://api.authsignal.com/v1" # optional
   export AUTHSIGNAL_ACTION="signInWithPasskeyAutofill"      # optional
   ```

   Use the API URL for your Authsignal region. Keep `AUTHSIGNAL_SECRET` on the server; never add it to the login page.

   With Docker Compose, pass the settings to the WSO2 service and keep the secret in a local `.env` file or secret manager:

   ```yaml
   services:
     wso2:
       environment:
         AUTHSIGNAL_SECRET: ${AUTHSIGNAL_SECRET}
         AUTHSIGNAL_API_URL: https://api.authsignal.com/v1
   ```

   For a WSO2 installation started directly from the host, export the variables in the service account's environment before running `wso2server.sh`. For a managed service, configure the same variables in its systemd, Kubernetes, ECS, or equivalent process definition.

4. Restart WSO2 and confirm the server log contains:

   ```text
   Authsignal passkey authenticator bundle activated
   ```

5. Add **Authsignal Passkey** to the application's sign-in flow. It can share the first authentication step with WSO2's Basic Authenticator so password login remains available.

## Enable passkey autofill on the stock login page

The server-side JAR cannot start WebAuthn inside the browser. The WSO2 login page must also load the Authsignal Browser SDK and mark its username input with `autocomplete="username webauthn"`.

1. Download the Authsignal Browser SDK into WSO2's `authenticationendpoint` webapp as `authsignal-browser.min.js`.
2. Copy [`login-page/authsignal-autofill.js`](login-page/authsignal-autofill.js) into the same webapp.
3. Copy [`login-page/authsignal-config.example.js`](login-page/authsignal-config.example.js) as `authsignal-config.js` and set the public tenant ID, regional API URL, and action.
4. Load the three scripts from WSO2's supported login-page customization or Basic Auth extension hook. [`login-page/basicauth-extensions.jsp.example`](login-page/basicauth-extensions.jsp.example) shows the required tags.

The separate **Sign in with Authsignal Passkey** authenticator button is optional when conditional UI is injected into the stock username field. WSO2 may still render it when the custom authenticator is configured as another option in the same step. The supplied browser script intercepts that specific Authsignal button and opens the explicit passkey picker on the stock WSO2 page instead of navigating to the standalone fallback page.

## Identity mapping

After Authsignal validates the passkey challenge, the authenticator uses the returned Authsignal `userId` as the WSO2 local username. That local user must already exist in the active WSO2 tenant.

For example, an Authsignal `userId` of `admin` maps to the WSO2 local user `admin`.

## Authentication flow

```text
Browser -> WSO2 login page -> Authsignal passkey challenge
        -> Authsignal result token -> WSO2 custom authenticator
        -> Authsignal /validate -> local WSO2 user -> OIDC tokens
```

The browser receives only the public Authsignal tenant configuration. WSO2 performs the token validation with the secret key before completing its authentication transaction.
