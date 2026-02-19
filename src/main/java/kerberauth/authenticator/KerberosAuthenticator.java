package kerberauth.authenticator;

import burp.api.montoya.http.message.requests.HttpRequest;

import kerberauth.config.Config;
import kerberauth.kerberos.KerberosManager;
import kerberauth.kerberos.ContextTokenSpnTriple;
import kerberauth.manager.UserManager;
import kerberauth.model.UserEntry;
import kerberauth.util.DomainUtil;
import kerberauth.util.LogUtil;
import kerberauth.util.RequestUtil;

import javax.security.auth.callback.CallbackHandler;
import org.ietf.jgss.GSSException;
import java.util.List;

/**
 * Authenticates HTTP requests with Kerberos SPNEGO tokens.
 * 
 * Responsibilities:
 * - Determine which user should authenticate the request
 * - Generate SPNEGO tokens
 * - Add Authorization header to requests
 * - Handle authentication failures gracefully
 */
public class KerberosAuthenticator {
    
    private static class Holder {
        static final KerberosAuthenticator INSTANCE = new KerberosAuthenticator();
    }
    
    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String NEGOTIATE_SCHEME = "Negotiate";
    
    private final KerberosManager kerberosManager;
    private final UserManager userManager;
    private final Config config;
    
    private KerberosAuthenticator() {
        this.kerberosManager = KerberosManager.getInstance();
        this.userManager = UserManager.getInstance();
        this.config = Config.getInstance();
    }
    
    /**
     * Get the singleton instance of KerberosAuthenticator.
     */
    public static KerberosAuthenticator getInstance() {
        return Holder.INSTANCE;
    }
    
    /**
     * Authenticate an HTTP request.
     * 
     * Determines the appropriate user, generates a token if needed,
     * and adds the Authorization header to the request.
     * 
     * @param request the HTTP request to authenticate
     */
    public HttpRequest authenticateRequest(HttpRequest request) {
        if (request == null) {
            LogUtil.log(Config.LogLevel.VERBOSE, 
                "Received null request for authentication");
            return request;
        }
        
        try {
            // Determine which user to use
            UserEntry user = selectUser(request);
            if (user == null) {
                LogUtil.log(Config.LogLevel.VERBOSE, 
                    "No user selected for request for host: " + RequestUtil.extractHostname(request));
                return request;
            }
            
            // Ensure user is authenticated
            if (!user.hasActiveLogin()) {
                authenticateUser(user);
            }
            
            // Generate token for the target host
            String hostname = RequestUtil.extractHostname(request);
            if (hostname == null || hostname.isEmpty()) {
                LogUtil.log(Config.LogLevel.VERBOSE, 
                    "Could not extract hostname from request");
                return request;
            }
            
            List<String> spns = DomainUtil.resolveSpns(hostname);
            ContextTokenSpnTriple ctst = kerberosManager.getTokenForDefaultUser(spns);
            if (ctst == null || ctst.getToken() == null) {
                LogUtil.log(Config.LogLevel.VERBOSE, 
                    "Failed to generate token for host: " + hostname);
                return request;
            }
            String token = ctst.getToken();

            // Cache the successful hostname→SPN mapping for future requests
            if (ctst.getSpn() != null) {
                kerberauth.cache.CacheManager.getInstance().putHostnameToSpn(hostname, ctst.getSpn());
            }
            
            // Add Authorization header
            HttpRequest newRequest = addAuthorizationHeader(request, token);
            
            LogUtil.log(Config.LogLevel.VERBOSE, 
                "Added Kerberos authentication for user: " + user.getPrincipal());
            
            return newRequest;
            
        } catch (GSSException gsse) {
            LogUtil.log(Config.LogLevel.NORMAL, 
                "Failed to generate SPNEGO token: " + gsse.getMessage());
            LogUtil.logException(Config.LogLevel.VERBOSE, gsse);
        } catch (Exception e) {
            LogUtil.log(Config.LogLevel.NORMAL, 
                "Error during request authentication: " + e.getMessage());
            LogUtil.logException(Config.LogLevel.VERBOSE, e);
        }

        // In case of any failure, return the original request unmodified
        return request;
    }
    
    /**
     * Select the appropriate user for this request.
     * 
     * Selection priority:
     * 1. Header-based selection (e.g., from pwnfox header)
     * 2. Default user
     * 
     * @param request the HTTP request
     * @return the selected UserEntry or null
     */
    private UserEntry selectUser(HttpRequest request) {
        // Try header-based selection first
        String headerValue = RequestUtil.getCustomHeaderValue(request);
        if (headerValue != null && !headerValue.isEmpty()) {
            UserEntry user = userManager.getUserByHeaderValue(headerValue);
            if (user != null) {
                LogUtil.log(Config.LogLevel.VERBOSE, 
                    "Selected user via header value: " + headerValue);
                return user;
            }
        }
        
        // Fall back to default user
        UserEntry defaultUser = userManager.getDefaultUser();
        if (defaultUser != null) {
            LogUtil.log(Config.LogLevel.VERBOSE, 
                "Selected default user: " + defaultUser.getUsername());
        }
        return defaultUser;
    }
    
    /**
     * Authenticate a user.
     * 
     * @param user the UserEntry to authenticate
     */
    private void authenticateUser(UserEntry user) {
        try {
            // Create a callback handler that provides credentials
            CallbackHandler handler = new KerberosCallbackHandler(user);
            
            // Authenticate through KerberosManager
            kerberosManager.authenticateUserEntry(user, handler);
            
        } catch (Exception e) {
            LogUtil.log(Config.LogLevel.NORMAL, 
                "Failed to authenticate user " + user.getPrincipal() + ": " + e.getMessage());
            LogUtil.logException(Config.LogLevel.VERBOSE, e);
        }
    }
    
    /**
     * Add the Authorization header to an HTTP request.
     * 
     * @param request the HTTP request
     * @param token the SPNEGO token (Base64-encoded)
     * @return the modified HTTP request with the Authorization header
     */
    private HttpRequest addAuthorizationHeader(HttpRequest request, String token) {
        String headerValue = NEGOTIATE_SCHEME + " " + token;
        HttpRequest newRequest = request.withAddedHeader(AUTHORIZATION_HEADER, headerValue);
        
        // Update the message with the new request
        return newRequest;
    }
    
    /**
     * Check if authentication is enabled in the extension configuration.
     * 
     * @return true if Kerberos authentication should be applied
     */
    public boolean isAuthenticationEnabled() {
        return config.isKerberosEnabled() && userManager.hasUsers();
    }
    
    /**
     * Clear all user logins.
     * Useful for extension unload or reset.
     */
    public void resetAuthentication() {
        kerberosManager.logoutAll();
        LogUtil.log(Config.LogLevel.VERBOSE, 
            "Authentication state reset");
    }

}
