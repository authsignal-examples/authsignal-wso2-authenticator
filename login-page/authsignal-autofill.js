(function () {
    "use strict";

    var usernameInput = document.getElementById("usernameUserInput");
    var passwordInput = document.getElementById("password");
    var loginForm = document.getElementById("loginForm");
    var passkeyButton = document.getElementById("authsignal-passkey-button") ||
        document.querySelector('[data-testid="login-page-sign-in-with-AuthsignalPasskeyAuthenticator"]');

    if (!usernameInput || !loginForm) {
        return;
    }

    usernameInput.setAttribute("autocomplete", "username webauthn");
    if (passwordInput) {
        passwordInput.setAttribute("autocomplete", "current-password");
    }

    var config = window.authsignalWso2Config || {};
    if (!config.tenantId) {
        console.error("Authsignal tenantId is not configured");
        return;
    }

    if (!window.authsignal || !window.authsignal.Authsignal) {
        console.error("Authsignal browser SDK did not load");
        return;
    }

    var client = new window.authsignal.Authsignal({
        tenantId: config.tenantId,
        baseUrl: config.baseUrl || "https://api.authsignal.com/v1"
    });
    var action = config.action || "signInWithPasskeyAutofill";
    var params = new URLSearchParams(window.location.search);
    var isStandalonePage = window.location.pathname.endsWith("/authsignal-passkey-login.html");
    var explicitPrompt = params.get("authsignalPrompt") === "1" || isStandalonePage;

    function startSignIn(autofill) {
        client.passkey.signIn({ action: action, autofill: autofill }).then(function (result) {
            if (result.error) {
                console.error("Authsignal passkey sign-in failed", result.errorCode || result.error);
                return;
            }

            if (!result.data || !result.data.token) {
                return;
            }

            appendHiddenInput("authsignalToken", result.data.token);
            appendHiddenInput("idp", "LOCAL");
            appendHiddenInput("authenticator", "AuthsignalPasskeyAuthenticator");

            // Bypass WSO2's password-field validation. The custom authenticator
            // validates the Authsignal result token on the server.
            HTMLFormElement.prototype.submit.call(loginForm);
        }).catch(function (error) {
            console.error("Could not start Authsignal passkey sign-in", error);
        });
    }

    if (passkeyButton) {
        // WSO2's generated button normally redirects to the authenticator's
        // standalone page. Replace that handler so an explicit passkey prompt
        // opens from the stock login page. Reloading the same page first
        // cancels the pending conditional WebAuthn request.
        passkeyButton.removeAttribute("onclick");
        passkeyButton.addEventListener("click", function (event) {
            event.preventDefault();
            event.stopImmediatePropagation();

            if (explicitPrompt) {
                startSignIn(false);
                return;
            }

            var promptUrl = new URL(window.location.href);
            promptUrl.searchParams.set("authsignalPrompt", "1");
            window.location.assign(promptUrl.toString());
        }, true);
    }

    startSignIn(!explicitPrompt);

    function appendHiddenInput(name, value) {
        var input = document.createElement("input");
        input.type = "hidden";
        input.name = name;
        input.value = value;
        loginForm.appendChild(input);
    }
})();
