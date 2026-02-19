package kerberauth.kerberos;

import kerberauth.config.Config;
import kerberauth.manager.UserManager;
import kerberauth.model.UserEntry;
import kerberauth.ui.DelegationSettingsPanel;
import kerberauth.util.LogUtil;

import java.util.List;

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import org.ietf.jgss.GSSException;

/**
 * Orchestrates Kerberos authentication and token generation.
 * 
 * Responsibilities:
 * - Select user via UserManager
 * - Create LoginContext via LoginContextFactory
 * - Generate SPNEGO tokens via GssTokenGenerator
 * - Manage authentication lifecycle
 */
public class KerberosManager {
    
    private static class Holder {
        static final KerberosManager INSTANCE = new KerberosManager();
    }
    
    private final UserManager userManager;
    private final GssTokenGenerator tokenGenerator;
    
    private KerberosManager() {
        this.userManager = UserManager.getInstance();
        this.tokenGenerator = new GssTokenGenerator();
    }
    
    /**
     * Get the singleton instance of KerberosManager.
     */
    public static KerberosManager getInstance() {
        return Holder.INSTANCE;
    }
    
    /**
     * Authenticate a user by username and password.
     * Creates a LoginContext and associates it with the UserEntry.
     * 
     * @param username the Kerberos username
     * @param callbackHandler the CallbackHandler for credential prompts
     * @return true if authentication succeeded
     * @throws LoginException if authentication fails
     */
    public boolean authenticateUser(String username, CallbackHandler callbackHandler) throws LoginException {
        UserEntry user = userManager.getUserByUsername(username);
        if (user == null) {
            LogUtil.alertAndLog(Config.LogLevel.NORMAL, 
                "User not found: " + username);
            throw new LoginException("User not found: " + username);
        }
        
        return authenticateUserEntry(user, callbackHandler);
    }
    
    /**
     * Authenticate a user by header value (for header-based selection).
     * 
     * @param headerValue the value from the custom header (e.g., pwnfox)
     * @param callbackHandler the CallbackHandler for credential prompts
     * @return true if authentication succeeded
     * @throws LoginException if authentication fails
     */
    public boolean authenticateByHeaderValue(String headerValue, CallbackHandler callbackHandler) throws LoginException {
        UserEntry user = userManager.getUserByHeaderValue(headerValue);
        if (user == null) {
            LogUtil.alertAndLog(Config.LogLevel.NORMAL, 
                "User not found for header value: " + headerValue);
            throw new LoginException("User not found for header value: " + headerValue);
        }
        
        return authenticateUserEntry(user, callbackHandler);
    }
    
    /**
     * Authenticate the default user.
     * 
     * @param callbackHandler the CallbackHandler for credential prompts
     * @return true if authentication succeeded
     * @throws LoginException if authentication fails
     */
    public boolean authenticateDefaultUser(CallbackHandler callbackHandler) throws LoginException {
        UserEntry user = userManager.getDefaultUser();
        if (user == null) {
            LogUtil.alertAndLog(Config.LogLevel.NORMAL, 
                "No default user configured");
            throw new LoginException("No default user configured");
        }
        
        return authenticateUserEntry(user, callbackHandler);
    }
    
    /**
     * Internal method to authenticate a UserEntry.
     * 
     * @param user the UserEntry to authenticate
     * @param callbackHandler the CallbackHandler for credentials
     * @return true if authentication succeeded
     * @throws LoginException if authentication fails
     */
    public boolean authenticateUserEntry(UserEntry user, CallbackHandler callbackHandler) throws LoginException {
        // Invalidate any existing login first
        user.invalidateLogin();
        
        try {
            LogUtil.log(Config.LogLevel.VERBOSE, 
                "Authenticating user: " + user.getPrincipal());
            
            // Create LoginContext with callback handler
            LoginContext lc = LoginContextFactory.createLoginContext(user, callbackHandler);
            
            // Perform the login
            lc.login();
            
            // Associate the LoginContext with the user
            user.setLoginContext(lc);
            
            // Check if TGT is forwardable (required for delegation)
            boolean forwardable = DelegationSettingsPanel.checkTgtForwardableFlag(lc.getSubject());
            if (forwardable) {
                LogUtil.log(Config.LogLevel.NORMAL,
                    "TGT is forwardable — delegation should work OK");
            } else {
                LogUtil.alertAndLog(Config.LogLevel.NORMAL,
                    "TGT is not forwardable — delegation will not work. "
                    + "Use Delegation panel to create/set a krb5.conf with \"forwardable = true\".");
            }
            
            LogUtil.alertAndLog(Config.LogLevel.NORMAL, 
                "Successfully authenticated: " + user.getPrincipal());
            
            return true;
            
        } catch (LoginException le) {
            LogUtil.log(Config.LogLevel.NORMAL, 
                "Authentication failed for " + user.getPrincipal() + ": " + le.getMessage());
            throw le;
        }
    }
    
    /**
     * Generate a SPNEGO token for a user to access a service.
     * 
     * @param username the Kerberos username
     * @param spns the Service Principal Names (e.g., "HTTP/host.example.com@REALM")
     * @return the Base64-encoded SPNEGO token
     * @throws GSSException if token generation fails
     */
    public ContextTokenSpnTriple getTokenForUser(String username, List<String> spns) throws GSSException {
        UserEntry user = userManager.getUserByUsername(username);
        if (user == null) {
            LogUtil.alertAndLog(Config.LogLevel.NORMAL, 
                "User not found: " + username);
            throw new GSSException(GSSException.NO_CRED, -1, "User not found: " + username);
        }
        
        return tokenGenerator.generateToken(user, spns);
    }
    
    /**
     * Generate a SPNEGO token by header value.
     * 
     * @param headerValue the value from the custom header
     * @param spns the Service Principal Names
     * @return the Base64-encoded SPNEGO token
     * @throws GSSException if token generation fails
     */
    public ContextTokenSpnTriple getTokenByHeaderValue(String headerValue, List<String> spns) throws GSSException {
        UserEntry user = userManager.getUserByHeaderValue(headerValue);
        if (user == null) {
            LogUtil.alertAndLog(Config.LogLevel.NORMAL, 
                "User not found for header value: " + headerValue);
            throw new GSSException(GSSException.NO_CRED, -1, "User not found for header value: " + headerValue);
        }
        
        return tokenGenerator.generateToken(user, spns);
    }
    
    /**
     * Generate a SPNEGO token for the default user.
     * 
     * @param spns the Service Principal Names
     * @return the Base64-encoded SPNEGO token
     * @throws GSSException if token generation fails
     */
    public ContextTokenSpnTriple getTokenForDefaultUser(List<String> spns) throws GSSException {
        UserEntry user = userManager.getDefaultUser();
        if (user == null) {
            LogUtil.alertAndLog(Config.LogLevel.NORMAL, 
                "No default user configured");
            throw new GSSException(GSSException.NO_CRED, -1, "No default user configured");
        }
        
        return tokenGenerator.generateToken(user, spns);
    }
    
    /**
     * Check if a user is currently logged in.
     * 
     * @param username the Kerberos username
     * @return true if the user has an active login
     */
    public boolean isUserLoggedIn(String username) {
        UserEntry user = userManager.getUserByUsername(username);
        if (user == null) {
            return false;
        }
        return user.hasActiveLogin();
    }
    
    /**
     * Check if any configured users are logged in.
     * 
     * @return true if at least one user has an active login
     */
    public boolean hasActiveLogins() {
        for (UserEntry user : userManager.getAllUsers().values()) {
            if (user.hasActiveLogin()) {
                return true;
            }
        }
        return false;
    }
    
    /**
     * Logout a specific user.
     * 
     * @param username the Kerberos username
     */
    public void logoutUser(String username) {
        UserEntry user = userManager.getUserByUsername(username);
        if (user != null) {
            user.invalidateLogin();
            LogUtil.log(Config.LogLevel.VERBOSE, 
                "Logged out user: " + username);
        }
    }
    
    /**
     * Logout all users.
     * Useful for extension unload or reset.
     */
    public void logoutAll() {
        userManager.invalidateAllLogins();
        LogUtil.log(Config.LogLevel.VERBOSE, 
            "Logged out all users");
    }
    
    /**
     * Attempt a login with a guaranteed-invalid user to verify
     * that the KDC is reachable and responding to Kerberos requests.
     * A "Client not found" error confirms successful KDC contact.
     */
    public void loginTestUser() throws LoginException {
        String testPrincipal = "kerberauth_connectivity_test_" + System.nanoTime()
                + "@" + Config.getInstance().getRealmName();
        LoginContext lc = LoginContextFactory.createLoginContext(null,
            new javax.security.auth.callback.CallbackHandler() {
                @Override
                public void handle(javax.security.auth.callback.Callback[] callbacks) {
                    for (javax.security.auth.callback.Callback cb : callbacks) {
                        if (cb instanceof javax.security.auth.callback.NameCallback nc) {
                            nc.setName(testPrincipal);
                        } else if (cb instanceof javax.security.auth.callback.PasswordCallback pc) {
                            pc.setPassword("test_password_kerberauthauth".toCharArray());
                        }
                    }
                }
            });
        lc.login();
    }
}
