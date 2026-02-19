package kerberauth.kerberos;

import kerberauth.authenticator.KerberosCallbackHandler;
import kerberauth.cache.CacheManager;
import kerberauth.config.Config;
import kerberauth.model.UserEntry;
import kerberauth.util.LogUtil;

import java.util.List;
import java.util.concurrent.CompletionException;

import javax.security.auth.Subject;
import javax.security.auth.login.LoginException;
import org.ietf.jgss.*;

/**
 * Generates SPNEGO tokens for authenticated Kerberos users.
 * 
 * - Uses the LoginContext / Subject from a UserEntry.
 * - Generates an initial token for a given service principal (SPN).
 */
public class GssTokenGenerator {

    /**
     * Generate an initial SPNEGO token for a given service (SPN) for a logged-in user.
     *
     * @param user the UserEntry which must have an active LoginContext
     * @param spns the Service Principal Names (e.g., "HTTP/host.example.com@REALM")
     * @return Base64-encoded string containing the SPNEGO token
     * @throws GSSException if token generation fails
     */
    public ContextTokenSpnTriple generateToken(UserEntry user, List<String> spns) throws GSSException {
        Subject subject = user.getSubject();
        if (subject == null) {
            LogUtil.alertAndLog(Config.LogLevel.NORMAL, "User " + user.getPrincipal() + " is not logged in; cannot generate SPNEGO token.");
            throw new GSSException(GSSException.NO_CRED, -1, "User is not logged in");
        }

        CacheManager cacheManager = CacheManager.getInstance();

        try {
            CallableTokenAction action = new CallableTokenAction(spns);
            ContextTokenSpnTriple ctst = Subject.callAs(subject, action);

            // Mark the successful SPN as working
            if (ctst != null && ctst.getSpn() != null) {
                cacheManager.markWorking(ctst.getSpn());
            }

            return ctst;
        } catch (CompletionException ce) {
            Throwable cause = ce.getCause();

            if (cause instanceof TGTExpiredException) {
                LogUtil.alertAndLog(Config.LogLevel.NORMAL,
                    "TGT expired for user " + user.getPrincipal() + ". Attempting to re-authenticate...");

                // Invalidate the old login and try to get a new TGT
                user.invalidateLogin();

                if (!reAuthenticate(user)) {
                    LogUtil.alertAndLog(Config.LogLevel.NORMAL,
                        "Re-authentication failed for user " + user.getPrincipal());
                    throw new GSSException(GSSException.CREDENTIALS_EXPIRED, -1, "TGT expired and re-authentication failed");
                }

                // Retry token generation with the new TGT
                try {
                    Subject newSubject = user.getSubject();
                    CallableTokenAction retryAction = new CallableTokenAction(spns);
                    ContextTokenSpnTriple ctst = Subject.callAs(newSubject, retryAction);

                    if (ctst != null && ctst.getSpn() != null) {
                        cacheManager.markWorking(ctst.getSpn());
                    }

                    return ctst;
                } catch (CompletionException retryEx) {
                    LogUtil.alertAndLog(Config.LogLevel.NORMAL,
                        "Token generation failed after re-authentication: " + retryEx.getMessage());
                    LogUtil.logException(Config.LogLevel.VERBOSE, retryEx);
                    for (String spn : spns) {
                        cacheManager.markSpnFailed(spn);
                    }
                    throw new GSSException(GSSException.FAILURE, -1, "Token generation failed after TGT renewal");
                }

            } else {
                LogUtil.alertAndLog(Config.LogLevel.NORMAL,
                    "Exception in generateToken: " + ce.getMessage());
                LogUtil.logException(Config.LogLevel.VERBOSE, ce);
                for (String spn : spns) {
                    cacheManager.markSpnFailed(spn);
                }
                if (cause instanceof GSSException) {
                    throw (GSSException) cause;
                }
                throw new GSSException(GSSException.FAILURE, -1, "Token generation failed: " + ce.getMessage());
            }
        }
    }

    /**
     * Attempt to re-authenticate a user using their stored credentials.
     *
     * @param user the UserEntry to re-authenticate
     * @return true if re-authentication succeeded
     */
    private boolean reAuthenticate(UserEntry user) {
        try {
            KerberosCallbackHandler handler = new KerberosCallbackHandler(user);
            KerberosManager.getInstance().authenticateUserEntry(user, handler);
            LogUtil.log(Config.LogLevel.VERBOSE, "Re-authentication succeeded for " + user.getPrincipal());
            return true;
        } catch (LoginException e) {
            LogUtil.alertAndLog(Config.LogLevel.NORMAL,
                "Re-authentication failed for " + user.getPrincipal() + ": " + e.getMessage());
            LogUtil.logException(Config.LogLevel.VERBOSE, e);
            return false;
        }
    }
}
