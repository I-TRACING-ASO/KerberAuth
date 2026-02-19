package kerberauth.model;

import javax.security.auth.Subject;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

import kerberauth.config.Config;

import java.util.Objects;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Represents a Kerberos user configured in the extension.
 * 
 * Notes:
 * - Only password-based authentication is supported for this project.
 * - Secrets (password) are kept in-memory only (transient).
 * - LoginContext is transient and protected by a lock.
 */
public class UserEntry {

    private String username;
    private String headerSelectorValue; // value used to select this user via custom header
    private boolean enabled = true; // whether this user is enabled for authentication

    // Secrets and session state (transient: do not persist)
    private transient char[] password; // in-memory only
    private transient LoginContext loginContext;
    private transient long lastLoginTime;

    // Lock to protect loginContext and sensitive state
    private final ReentrantLock lock = new ReentrantLock();

    /**
     * Create a new UserEntry.
     *
     * @param id unique identifier for this user entry
     * @param username Kerberos username (e.g. user)
     */
    public UserEntry(String username, String passwordString) {
        this.username = Objects.requireNonNull(username, "username must not be null");
        this.password = passwordString.toCharArray();
    }

    public UserEntry(String username, String passwordString, String headerSelectorValue) {
        this(username, passwordString);
        this.headerSelectorValue = headerSelectorValue;
    }

    // ----------------------
    // Basic getters/setters
    // ----------------------

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getHeaderSelectorValue() {
        return headerSelectorValue;
    }

    public void setHeaderSelectorValue(String headerSelectorValue) {
        this.headerSelectorValue = headerSelectorValue;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    /**
     * Get the in-memory password. Caller should treat the returned array as sensitive.
     *
     * @return password char[] or null if none set
     */
    public char[] getPassword() {
        return password;
    }

    /**
     * Returns true if a non-empty password is set for this user.
     */
    public boolean hasPassword() {
        return password != null && password.length > 0;
    }

    /**
     * Set the in-memory password. This is stored transiently and must not be persisted.
     *
     * @param password char[] password (caller retains ownership)
     */
    public void setPassword(String passwordString) {
        this.password = passwordString.toCharArray();
    }

    public long getLastLoginTime() {
        return lastLoginTime;
    }

    // ----------------------
    // LoginContext management
    // ----------------------

    /**
     * Returns true if a LoginContext is currently associated with this user.
     */
    public boolean hasActiveLogin() {
        lock.lock();
        try {
            return loginContext != null;
        } finally {
            lock.unlock();
        }
    }

    /**
     * Return the JAAS Subject for this user's active LoginContext, or null if none.
     */
    public Subject getSubject() {
        lock.lock();
        try {
            return (loginContext != null) ? loginContext.getSubject() : null;
        } finally {
            lock.unlock();
        }
    }

    /**
     * Associate a LoginContext with this UserEntry. If an existing LoginContext is present,
     * it is logged out first to avoid resource leaks.
     *
     * This method does not perform the login itself; KerberosManager should create the
     * LoginContext (using the appropriate CallbackHandler) and then call this setter.
     *
     * @param lc the LoginContext to associate (may be null to clear)
     */
    public void setLoginContext(LoginContext lc) {
        lock.lock();
        try {
            if (this.loginContext != null) {
                try {
                    this.loginContext.logout();
                } catch (LoginException e) {
                    // ignore logout failure but clear context anyway
                }
            }
            this.loginContext = lc;
            this.lastLoginTime = (lc != null) ? System.currentTimeMillis() : 0L;
        } finally {
            lock.unlock();
        }
    }

    /**
     * Retrieve the currently associated LoginContext (may be null).
     *
     * @return the LoginContext or null
     */
    public LoginContext getLoginContext() {
        lock.lock();
        try {
            return loginContext;
        } finally {
            lock.unlock();
        }
    }

    /**
     * Invalidate and clear the active LoginContext for this user.
     * This will call logout() on the LoginContext if present.
     */
    public void invalidateLogin() {
        lock.lock();
        try {
            if (loginContext != null) {
                try {
                    loginContext.logout();
                } catch (LoginException e) {
                    // ignore logout errors
                } finally {
                    loginContext = null;
                    lastLoginTime = 0L;
                }
            }
        } finally {
            lock.unlock();
        }
    }

    public String getPrincipal() {
        Config config = Config.getInstance();
        String realm = config.getRealmName();
        if (realm != null && !realm.isEmpty()) {
            return username + "@" + realm;
        } else {
            return username;
        }
    }

    public void setPrincipal(String principal) {
        // Extract username from principal (format: username@REALM)
        if (principal != null && principal.contains("@")) {
            this.username = principal.substring(0, principal.indexOf("@"));
        } else {
            this.username = principal;
        }
    }

}
