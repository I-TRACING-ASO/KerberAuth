package kerberauth.manager;

import kerberauth.config.Config;
import kerberauth.model.UserEntry;
import kerberauth.util.LogUtil;

import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * Manages UserEntry instances for all configured Kerberos users.
 * 
 * Responsibilities:
 * - Initialize UserEntry objects from Config
 * - Provide user selection (by header value, default, etc.)
 * - Manage user lifecycle (login/logout)
 */
public class UserManager {
    
    private static class Holder {
        static final UserManager INSTANCE = new UserManager();
    }
    
    public static UserManager getInstance() {
        return Holder.INSTANCE;
    }
    
    // Thread-safe storage for UserEntry instances
    private final Map<String, UserEntry> usersByUsername;
    private final Map<String, UserEntry> usersByHeaderValue;
    private final ReentrantReadWriteLock lock;
    
    private UserManager() {
        this.usersByUsername = new HashMap<>();
        this.usersByHeaderValue = new HashMap<>();
        this.lock = new ReentrantReadWriteLock();
    }
    
    /**
     * Initialize the UserManager with users from Config.
     * This should be called once during extension initialization.
     */
    public void initialize() {
        syncFromConfig(true);
    }

    /**
     * Re-synchronize UserManager from Config, preserving Kerberos sessions
     * for users whose username and password have not changed.
     * New users are added, removed users are logged out, and metadata
     * (header selector, enabled) is updated in-place.
     */
    public void syncFromConfig() {
        syncFromConfig(false);
    }

    private void syncFromConfig(boolean fullReset) {
        Config config = Config.getInstance();
        List<String[]> users = config.getUsers();
        
        lock.writeLock().lock();
        try {
            if (fullReset) {
                usersByUsername.clear();
                usersByHeaderValue.clear();
            }

            if (users == null || users.isEmpty()) {
                // Logout all existing users before clearing
                for (UserEntry ue : usersByUsername.values()) {
                    ue.invalidateLogin();
                }
                usersByUsername.clear();
                usersByHeaderValue.clear();
                LogUtil.alertAndLog(Config.LogLevel.NORMAL, 
                    "No users configured in Config. KerberAuth will not be functional.");
                return;
            }

            // Track which usernames are still present in the new config
            Set<String> newUsernames = new HashSet<>();
            // Rebuild header map from scratch (header values may have changed)
            usersByHeaderValue.clear();
            
            for (String[] user : users) {
                if (user[0] == null || user[0].isEmpty()) {
                    LogUtil.alertAndLog(Config.LogLevel.NORMAL, 
                        "Skipping user with null or empty username");
                    continue;
                }
                
                String username = user[0];
                String password = (user.length > 1 && user[1] != null) ? user[1] : "";
                String headerValue = (user.length > 2) ? user[2] : null;
                boolean enabled = (user.length > 3) ? Boolean.parseBoolean(user[3]) : true;
                
                newUsernames.add(username);
                
                UserEntry existing = usersByUsername.get(username);
                if (existing != null && !fullReset) {
                    // User already exists — update metadata, preserve session
                    existing.setHeaderSelectorValue(headerValue);
                    existing.setEnabled(enabled);
                    // If password changed, invalidate the Kerberos session
                    if (!password.equals(new String(existing.getPassword()))) {
                        existing.setPassword(password);
                        existing.invalidateLogin();
                        LogUtil.log(Config.LogLevel.VERBOSE,
                            "Password changed for user: " + username + " — session invalidated");
                    }
                } else {
                    // New user — create fresh entry
                    UserEntry userEntry = new UserEntry(username, password, headerValue);
                    userEntry.setEnabled(enabled);
                    usersByUsername.put(username, userEntry);
                    LogUtil.log(Config.LogLevel.VERBOSE, "Added user: " + username);
                }
                
                // Rebuild header index
                if (headerValue != null && !headerValue.isEmpty()) {
                    UserEntry entry = usersByUsername.get(username);
                    UserEntry dup = usersByHeaderValue.put(headerValue, entry);
                    if (dup != null && !dup.getUsername().equals(username)) {
                        LogUtil.alertAndLog(Config.LogLevel.NORMAL,
                            "Duplicate header selector '" + headerValue
                            + "': user '" + username
                            + "' overrides '" + dup.getUsername() + "'");
                    }
                }
            }
            
            // Remove users that are no longer in config
            Set<String> removed = new HashSet<>(usersByUsername.keySet());
            removed.removeAll(newUsernames);
            for (String gone : removed) {
                UserEntry ue = usersByUsername.remove(gone);
                if (ue != null) {
                    ue.invalidateLogin();
                    LogUtil.log(Config.LogLevel.VERBOSE, "Removed user: " + gone);
                }
            }
            
            LogUtil.log(Config.LogLevel.VERBOSE, 
                "UserManager synced: " + usersByUsername.size() + " user(s)");
                
        } finally {
            lock.writeLock().unlock();
        }
    }
    
    /**
     * Get a UserEntry by username.
     * 
     * @param username the Kerberos username
     * @return the UserEntry or null if not found
     */
    public UserEntry getUserByUsername(String username) {
        lock.readLock().lock();
        try {
            return usersByUsername.get(username);
        } finally {
            lock.readLock().unlock();
        }
    }
    
    /**
     * Get a UserEntry by header selector value (e.g., for pwnfox integration).
     * 
     * @param headerValue the value from the custom header
     * @return the UserEntry or null if not found
     */
    public UserEntry getUserByHeaderValue(String headerValue) {
        if (headerValue == null || headerValue.isEmpty()) {
            return null;
        }
        
        lock.readLock().lock();
        try {
            return usersByHeaderValue.get(headerValue);
        } finally {
            lock.readLock().unlock();
        }
    }
    
    /**
     * Get all configured users.
     * 
     * @return a copy of the users map
     */
    public Map<String, UserEntry> getAllUsers() {
        lock.readLock().lock();
        try {
            return new HashMap<>(usersByUsername);
        } finally {
            lock.readLock().unlock();
        }
    }

    /**
     * Add a new user to the manager.
     * 
     * @param username the Kerberos username
     * @param password the password for the user
     * @param headerValue header selector value
     */
    public void addUser(String username, String password, String headerValue) {
        if (username == null || username.isEmpty()) {
            LogUtil.alertAndLog(Config.LogLevel.NORMAL, "Cannot add null or invalid user");
            return;
        }

        lock.writeLock().lock();
        try {
            UserEntry user = new UserEntry(username, password, headerValue);
            usersByUsername.put(user.getUsername(), user);
            if (headerValue != null && !headerValue.isEmpty()) {
                usersByHeaderValue.put(headerValue, user);
            }
            LogUtil.log(Config.LogLevel.VERBOSE, "Added user: " + user.getUsername());
        } finally {
            lock.writeLock().unlock();
        }
    }

    /**
     * Add a new user without header selector value.
     * 
     * @param username the Kerberos username
     * @param password the password for the user
     */
    public void addUser(String username, String password) {
        addUser(username, password, null);
    }

    /**
     * Invalidate all active logins for all users.
     * Useful for cleanup or reset operations.
     */
    public void invalidateAllLogins() {
        lock.readLock().lock();
        try {
            for (UserEntry user : usersByUsername.values()) {
                user.invalidateLogin();
            }
            LogUtil.log(Config.LogLevel.VERBOSE, "Invalidated all user logins");
        } finally {
            lock.readLock().unlock();
        }
    }
    
    /**
     * Check if any users are configured.
     * 
     * @return true if at least one user is configured
     */
    public boolean hasUsers() {
        lock.readLock().lock();
        try {
            return !usersByUsername.isEmpty();
        } finally {
            lock.readLock().unlock();
        }
    }

    /**
     * Get the default user, as designated in Config.
     * Falls back to the first enabled user if no default is set.
     * 
     * @return the default UserEntry or null if none found
     */
    public UserEntry getDefaultUser() {
        lock.readLock().lock();
        try {
            String defaultUsername = Config.getInstance().getDefaultUsername();
            if (defaultUsername != null) {
                UserEntry designated = usersByUsername.get(defaultUsername);
                if (designated != null && designated.isEnabled()) {
                    return designated;
                }
            }
            // Fallback: first enabled user
            for (UserEntry user : usersByUsername.values()) {
                if (user.isEnabled()) {
                    return user;
                }
            }
            return null;
        } finally {
            lock.readLock().unlock();
        }
    }
}
