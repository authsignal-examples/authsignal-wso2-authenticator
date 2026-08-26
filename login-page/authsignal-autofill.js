(function () {
    "use strict";

    var usernameInput = document.getElementById("usernameUserInput");
    var passwordInput = document.getElementById("password");
    var loginForm = document.getElementById("loginForm");

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

    client.passkey.signIn({ action: action, autofill: true }).then(function (result) {
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
        console.error("Could not start Authsignal passkey autofill", error);
    });

    function appendHiddenInput(name, value) {
        var input = document.createElement("input");
        input.type = "hidden";
        input.name = name;
        input.value = value;
        loginForm.appendChild(input);
    }
})();

