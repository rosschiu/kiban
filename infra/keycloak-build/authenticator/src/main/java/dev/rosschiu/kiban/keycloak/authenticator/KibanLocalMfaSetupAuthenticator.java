package dev.rosschiu.kiban.keycloak.authenticator;

import java.util.Set;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.credential.CredentialModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;

public final class KibanLocalMfaSetupAuthenticator implements Authenticator {
    private static final Logger LOG = Logger.getLogger(KibanLocalMfaSetupAuthenticator.class);

    // REQUIRED_MODE_ATTRIBUTE is written by the identity service's MFA policy sync
    // (internal/identity/sync.go) — a single shared vocabulary, no dual-write.
    private static final String REQUIRED_MODE_ATTRIBUTE = "kiban.login_security.required_mode";
    private static final String RUNTIME_MFA_ATTRIBUTE = "kiban.login_security.mfa";
    private static final String ROUTE_SESSION_NOTE = "kiban.auth_route";
    private static final String DECISION_SESSION_NOTE = "kiban.local_mfa_decision";
    private static final String CONFIGURE_TOTP = "CONFIGURE_TOTP";
    private static final String REGISTER_PASSKEY = "webauthn-register-passwordless";
    private static final Set<String> SSO_AUTH_NOTES = Set.of(
        "BROKERED_CONTEXT",
        "PBL_BROKERED_IDENTITY_CONTEXT",
        "broker.session.id",
        "identity_provider"
    );

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        UserModel user = context.getUser() != null ? context.getUser() : authSession.getAuthenticatedUser();
        if (user == null) {
            context.success();
            return;
        }

        if (isBrokeredSso(authSession)) {
            clearTransientLoginSecurityActions(authSession);
            clearUserLoginSecurityActions(user);
            authSession.setUserSessionNote(ROUTE_SESSION_NOTE, "sso");
            authSession.setUserSessionNote(DECISION_SESSION_NOTE, "sso_bypass_local_mfa");
            context.success();
            return;
        }

        authSession.setUserSessionNote(ROUTE_SESSION_NOTE, "keycloak");
        clearTransientLoginSecurityActions(authSession);
        String requiredMode = normalizeRequiredMode(user.getFirstAttribute(REQUIRED_MODE_ATTRIBUTE));
        CredentialState credentials = resolveCredentialState(user.getFirstAttribute(RUNTIME_MFA_ATTRIBUTE), user);
        String requiredAction = requiredActionFor(requiredMode, credentials);
        if (requiredAction != null) {
            authSession.addRequiredAction(requiredAction);
            authSession.setUserSessionNote(DECISION_SESSION_NOTE, "setup_required:" + requiredAction);
            LOG.debugf("Kiban local MFA setup required for user %s: mode=%s otp=%s passkey=%s action=%s", user.getId(), requiredMode, credentials.hasOtp, credentials.hasPasskey, requiredAction);
        } else {
            authSession.setUserSessionNote(DECISION_SESSION_NOTE, "satisfied:" + requiredMode + ":otp=" + credentials.hasOtp + ":passkey=" + credentials.hasPasskey);
        }
        context.success();
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        context.success();
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {}

    @Override
    public void close() {}

    private static boolean isBrokeredSso(AuthenticationSessionModel authSession) {
        for (String note : SSO_AUTH_NOTES) {
            String value = authSession.getAuthNote(note);
            if (value != null && !value.isBlank()) {
                return true;
            }
        }
        return false;
    }

    private static void clearTransientLoginSecurityActions(AuthenticationSessionModel authSession) {
        authSession.removeRequiredAction(CONFIGURE_TOTP);
        authSession.removeRequiredAction(REGISTER_PASSKEY);
    }

    private static void clearUserLoginSecurityActions(UserModel user) {
        user.removeRequiredAction(CONFIGURE_TOTP);
        user.removeRequiredAction(REGISTER_PASSKEY);
    }

    private static String normalizeRequiredMode(String value) {
        if ("none".equals(value) || "otp_required".equals(value) || "passkey_required".equals(value) || "otp_or_passkey_required".equals(value)) {
            return value;
        }
        if (value == null || value.isBlank()) {
            return "none";
        }
        return "passkey_required";
    }

    // CredentialState tracks both credential types explicitly rather than collapsing "which
    // credential(s) does this user have" into a single winner value: otp_required must be
    // satisfied ONLY by an actual OTP credential, never by an existing passkey, so each
    // required_mode branch inspects exactly the type(s) it cares about.
    private static final class CredentialState {
        final boolean hasOtp;
        final boolean hasPasskey;

        CredentialState(boolean hasOtp, boolean hasPasskey) {
            this.hasOtp = hasOtp;
            this.hasPasskey = hasPasskey;
        }
    }

    // resolveCredentialState: RUNTIME_MFA_ATTRIBUTE, when set to one of the authenticator's own
    // known values, is an explicit override (nothing currently writes this attribute, but the
    // Keycloak user-profile schema declares it, so a manual write must still be honored).
    // Otherwise inspect the user's actual stored credentials by TYPE — CredentialModel.OTP
    // ("otp") for OTP, "webauthn-passwordless" for passkey — never conflating the two.
    private static CredentialState resolveCredentialState(String runtimeMfaAttribute, UserModel user) {
        if ("otp".equals(runtimeMfaAttribute)) {
            return new CredentialState(true, false);
        }
        if ("passkey".equals(runtimeMfaAttribute)) {
            return new CredentialState(false, true);
        }
        if ("none".equals(runtimeMfaAttribute)) {
            return new CredentialState(false, false);
        }
        boolean hasOtp = user.credentialManager().getStoredCredentialsByTypeStream(CredentialModel.OTP).findAny().isPresent();
        boolean hasPasskey = user.credentialManager().getStoredCredentialsByTypeStream("webauthn-passwordless").findAny().isPresent();
        return new CredentialState(hasOtp, hasPasskey);
    }

    // requiredActionFor: otp_required is satisfied ONLY by an OTP credential (a passkey does
    // not count); otp_or_passkey_required is satisfied by EITHER; with neither configured under
    // otp_or_passkey_required, a true two-way chooser screen is not achievable with plain
    // required-action mechanics (Keycloak 26's required-action queue runs actions in sequence,
    // not as a selection UI) — the deterministic default is CONFIGURE_TOTP (OTP has materially
    // lower enrollment friction than registering a passkey: no platform authenticator/security
    // key required).
    private static String requiredActionFor(String requiredMode, CredentialState credentials) {
        switch (requiredMode) {
            case "none":
                return null;
            case "otp_required":
                return credentials.hasOtp ? null : CONFIGURE_TOTP;
            case "passkey_required":
                return credentials.hasPasskey ? null : REGISTER_PASSKEY;
            case "otp_or_passkey_required":
                if (credentials.hasOtp || credentials.hasPasskey) {
                    return null;
                }
                return CONFIGURE_TOTP;
            default:
                // normalizeRequiredMode never returns an unrecognized value (it maps anything
                // else to "passkey_required"), but fail closed to the strictest action if that
                // invariant is ever broken.
                return REGISTER_PASSKEY;
        }
    }
}
