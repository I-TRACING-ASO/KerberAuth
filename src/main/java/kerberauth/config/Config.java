package kerberauth.config;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

import burp.api.montoya.persistence.PersistedList;
import burp.api.montoya.persistence.PersistedObject;
import kerberauth.util.LogUtil;

/**
 * Thread-safe singleton holding global configuration for Kerberos authentication in the extension.
 * 
 * - This class is used to store and share configuration values across the extension.
 * - It is implemented as a thread-safe, lazy-loaded singleton.
 * - All mutable lists are thread-safe (CopyOnWriteArrayList) to avoid concurrent modification issues.
 */
public class Config {

    // ----------------------
    // Static Singleton
    // ----------------------

    // Holder for lazy-loaded singleton (thread-safe without explicit synchronization)
    private static class Holder {
        private static final Config INSTANCE = new Config();
    }

    /**
     * Return the singleton instance.
     *
     * @return Config singleton instance
     */
    public static Config getInstance() {
        return Holder.INSTANCE;
    }

    // ----------------------
    // Enums
    // ----------------------

    public enum AuthenticationStrategy {
        REACTIVE, PROACTIVE, PROACTIVE_401
    }

    public enum LogLevel {
        NONE, NORMAL, VERBOSE
    }

    // ----------------------
    // Config fields
    // ----------------------

    private volatile boolean kerberosEnabled = false;
    private volatile String domain;
    private volatile String kdc;
    private final List<String[]> users = new CopyOnWriteArrayList<>(); // String[]{username, password, header, enabled}
    private volatile boolean savePasswords = false;
    private volatile Path krb5ConfPath;
    private volatile AuthenticationStrategy authenticationStrategy = AuthenticationStrategy.REACTIVE;
    private volatile boolean everythingInScope = false;
    private volatile boolean wholeDomainInScope = true;
    private volatile boolean ignoreNTLMServers = false;
    private volatile boolean plainhostExpand = true;
    private final List<String> hostsInScope = new CopyOnWriteArrayList<>();
    private volatile LogLevel logLevel = LogLevel.NORMAL;
    private volatile LogLevel alertLevel = LogLevel.NORMAL;
    private final List<String> customSpns = new CopyOnWriteArrayList<>();
    private volatile String customHeader = "X-PwnFox-Color";
    private volatile String defaultUsername;
    private final Map<String, String> spnOverrides = new ConcurrentHashMap<>();

    // ----------------------
    // Private constructor
    // ----------------------

    private Config() {}

    // ----------------------
    // Getters / Setters
    // ----------------------

    public boolean isKerberosEnabled() {
        return kerberosEnabled;
    }

    public void setKerberosEnabled(boolean kerberosEnabled) {
        this.kerberosEnabled = kerberosEnabled;
    }

    public String getDomain() {
        return domain;
    }

    public void setDomain(String domain) {
        this.domain = domain;
    }

    public String getKdc() {
        return kdc;
    }

    public void setKdc(String kdc) {
        this.kdc = kdc;
    }

    public List<String[]> getUsers() {
        return Collections.unmodifiableList(users);
    }

    public void addUser(String[] user) {
        users.add(user);
    }

    public void removeUser(String[] user) {
        users.remove(user);
    }

    public void clearUsers() {
        users.clear();
    }

    public boolean isSavePasswords() {
        return savePasswords;
    }

    public void setSavePasswords(boolean savePasswords) {
        this.savePasswords = savePasswords;
    }

    public Path getKrb5ConfPath() {
        return krb5ConfPath;
    }

    public void setKrb5ConfPath(Path krb5ConfPath) {
        this.krb5ConfPath = krb5ConfPath;
    }

    public AuthenticationStrategy getAuthenticationStrategy() {
        return authenticationStrategy;
    }

    public void setAuthenticationStrategy(AuthenticationStrategy authenticationStrategy) {
        this.authenticationStrategy = authenticationStrategy;
    }

    public boolean isEverythingInScope() {
        return everythingInScope;
    }

    public void setEverythingInScope(boolean everythingInScope) {
        this.everythingInScope = everythingInScope;
    }

    public boolean isWholeDomainInScope() {
        return wholeDomainInScope;
    }

    public void setWholeDomainInScope(boolean wholeDomainInScope) {
        this.wholeDomainInScope = wholeDomainInScope;
    }

    public boolean isIgnoreNTLMServers() {
        return ignoreNTLMServers;
    }

    public void setIgnoreNTLMServers(boolean ignoreNTLMServers) {
        this.ignoreNTLMServers = ignoreNTLMServers;
    }

    public boolean isPlainhostExpand() {
        return plainhostExpand;
    }

    public void setPlainhostExpand(boolean plainhostExpand) {
        this.plainhostExpand = plainhostExpand;
    }

    public List<String> getHostsInScope() {
        return Collections.unmodifiableList(hostsInScope);
    }

    public void addHostInScope(String host) {
        hostsInScope.add(host);
    }

    public void removeHostInScope(String host) {
        hostsInScope.remove(host);
    }

    public void clearHostsInScope() {
        hostsInScope.clear();
    }

    public LogLevel getLogLevel() {
        return logLevel;
    }

    public void setLogLevel(LogLevel logLevel) {
        this.logLevel = logLevel;
    }

    public LogLevel getAlertLevel() {
        return alertLevel;
    }

    public void setAlertLevel(LogLevel alertLevel) {
        this.alertLevel = alertLevel;
    }

    public String getCustomHeader() {
        return customHeader;
    }

    public void setCustomHeader(String customHeader) {
        this.customHeader = customHeader;
    }

    public String getDefaultUsername() {
        return defaultUsername;
    }

    public void setDefaultUsername(String defaultUsername) {
        this.defaultUsername = defaultUsername;
    }

    public List<String> getCustomSpns() {
        return Collections.unmodifiableList(customSpns);
    }

    public void addCustomSpn(String spn) {
        if (spn != null && !spn.isEmpty()) {
            customSpns.add(spn);
        }
    }

    public void removeCustomSpn(String spn) {
        customSpns.remove(spn);
    }

    public void clearCustomSpns() {
        customSpns.clear();
    }

    public Map<String, String> getSpnOverrides() {
        return Collections.unmodifiableMap(spnOverrides);
    }

    public void putSpnOverride(String hostPattern, String customSpn) {
        if (hostPattern != null && !hostPattern.isEmpty()) {
            spnOverrides.put(hostPattern, customSpn);
        }
    }

    public void removeSpnOverride(String hostPattern) {
        spnOverrides.remove(hostPattern);
    }

    public void restoreDefaults() {
        kerberosEnabled = false;
        domain = null;
        kdc = null;
        users.clear();
        savePasswords = false;
        krb5ConfPath = null;
        authenticationStrategy = AuthenticationStrategy.REACTIVE;
        everythingInScope = false;
        wholeDomainInScope = true;
        ignoreNTLMServers = false;
        plainhostExpand = true;
        hostsInScope.clear();
        logLevel = LogLevel.NORMAL;
        alertLevel = LogLevel.NORMAL;
        customSpns.clear();
        customHeader = "X-PwnFox-Color";
        defaultUsername = null;
        spnOverrides.clear();
        LogUtil.log(LogLevel.NORMAL, "Configuration restored to defaults");
    }

    public void clearKerberosState() {
        users.clear();
        LogUtil.log(LogLevel.NORMAL, "Kerberos state cleared");
    }

    public void logKerberosTickets() {
        var userManager = kerberauth.manager.UserManager.getInstance();
        var allUsers = userManager.getAllUsers();
        if (allUsers.isEmpty()) {
            LogUtil.log(LogLevel.NORMAL, "No stored tickets (no users configured)");
            return;
        }
        int ticketCount = 1;
        boolean foundAny = false;
        for (var entry : allUsers.entrySet()) {
            var ue = entry.getValue();
            javax.security.auth.Subject subject = ue.getSubject();
            if (subject == null || subject.getPrivateCredentials() == null) continue;
            for (Object ob : subject.getPrivateCredentials()) {
                if (ob instanceof javax.security.auth.kerberos.KerberosTicket kt) {
                    foundAny = true;
                    LogUtil.log(LogLevel.NORMAL, String.format(
                            "=== TICKET %d - %s @ %s ==================",
                            ticketCount, kt.getClient(), kt.getServer()));
                    ticketCount++;
                    LogUtil.log(LogLevel.NORMAL, kt.toString());
                }
            }
        }
        if (!foundAny) {
            LogUtil.log(LogLevel.NORMAL, "No stored tickets");
        }
    }

    public void setKrb5Config() {
        System.setProperty("java.security.krb5.conf", krb5ConfPath.toString());
    }

    public String getRealmName() {
        if (domain == null || domain.isEmpty()) {
            return "";
        }
        return domain.toUpperCase();
    }

    public void setDomainAndKdc(String domainDnsName, String kdcHost) {
        this.domain = domainDnsName;
        this.kdc = kdcHost;

        if (domain == null || domain.isEmpty()) {
            LogUtil.alertAndLog(LogLevel.NORMAL, "No domain DNS name set");

            if (kdc == null || kdc.isEmpty()) {
                LogUtil.alertAndLog(LogLevel.NORMAL, "No KDC host set");
            }

            return;
        }

        // Invalidate all login contexts and clear caches on domain change
        kerberauth.manager.UserManager.getInstance().invalidateAllLogins();
        kerberauth.cache.CacheManager.getInstance().clearAll();

        System.setProperty("java.security.krb5.realm", domain.toUpperCase());
        System.setProperty("java.security.krb5.kdc", kdc);

        LogUtil.log(LogLevel.VERBOSE, String.format(
                "New domain DNS name (%s) and KDC hostname (%s) set",
                domainDnsName, kdcHost));
    }

    // ----------------------
    // Persistence
    // ----------------------

    private static final String KEY_KERBEROS_ENABLED = "kerberosEnabled";
    private static final String KEY_DOMAIN = "domain";
    private static final String KEY_KDC = "kdc";
    private static final String KEY_SAVE_PASSWORDS = "savePasswords";
    private static final String KEY_KRB5_CONF_PATH = "krb5ConfPath";
    private static final String KEY_AUTH_STRATEGY = "authenticationStrategy";
    private static final String KEY_EVERYTHING_IN_SCOPE = "everythingInScope";
    private static final String KEY_WHOLE_DOMAIN_IN_SCOPE = "wholeDomainInScope";
    private static final String KEY_IGNORE_NTLM = "ignoreNTLMServers";
    private static final String KEY_PLAINHOST_EXPAND = "plainhostExpand";
    private static final String KEY_HOSTS_IN_SCOPE = "hostsInScope";
    private static final String KEY_LOG_LEVEL = "logLevel";
    private static final String KEY_ALERT_LEVEL = "alertLevel";
    private static final String KEY_CUSTOM_SPNS = "customSpns";
    private static final String KEY_CUSTOM_HEADER = "customHeader";
    private static final String KEY_DEFAULT_USERNAME = "defaultUsername";
    private static final String KEY_USERS = "users";
    private static final String KEY_SPN_OVERRIDES_HOSTS = "spnOverridesHosts";
    private static final String KEY_SPN_OVERRIDES_SPNS = "spnOverridesSpns";

    /**
     * Save configuration to Burp's persisted extension data.
     */
    public void saveToPersistedData(PersistedObject data) {
        try {
            data.setBoolean(KEY_KERBEROS_ENABLED, kerberosEnabled);
            data.setString(KEY_DOMAIN, domain);
            data.setString(KEY_KDC, kdc);
            data.setBoolean(KEY_SAVE_PASSWORDS, savePasswords);
            data.setString(KEY_KRB5_CONF_PATH, krb5ConfPath != null ? krb5ConfPath.toString() : null);
            data.setString(KEY_AUTH_STRATEGY, authenticationStrategy.name());
            data.setBoolean(KEY_EVERYTHING_IN_SCOPE, everythingInScope);
            data.setBoolean(KEY_WHOLE_DOMAIN_IN_SCOPE, wholeDomainInScope);
            data.setBoolean(KEY_IGNORE_NTLM, ignoreNTLMServers);
            data.setBoolean(KEY_PLAINHOST_EXPAND, plainhostExpand);
            data.setStringList(KEY_HOSTS_IN_SCOPE, toPersistedList(hostsInScope));
            data.setString(KEY_LOG_LEVEL, logLevel.name());
            data.setString(KEY_ALERT_LEVEL, alertLevel.name());
            data.setStringList(KEY_CUSTOM_SPNS, toPersistedList(customSpns));
            data.setString(KEY_CUSTOM_HEADER, customHeader);
            data.setString(KEY_DEFAULT_USERNAME, defaultUsername);

            // Users: serialize as flat list [username, password, header, enabled, username, password, ...]
            List<String> flatUsers = new ArrayList<>();
            for (String[] user : users) {
                flatUsers.add(user.length > 0 ? user[0] : "");
                flatUsers.add(savePasswords && user.length > 1 ? user[1] : "");
                flatUsers.add(user.length > 2 && user[2] != null ? user[2] : "");
                flatUsers.add(user.length > 3 ? user[3] : "true");
            }
            data.setStringList(KEY_USERS, toPersistedList(flatUsers));

            // SPN overrides: parallel lists of hosts and spns
            List<String> overrideHosts = new ArrayList<>(spnOverrides.keySet());
            List<String> overrideSpns = new ArrayList<>();
            for (String host : overrideHosts) {
                overrideSpns.add(spnOverrides.get(host));
            }
            data.setStringList(KEY_SPN_OVERRIDES_HOSTS, toPersistedList(overrideHosts));
            data.setStringList(KEY_SPN_OVERRIDES_SPNS, toPersistedList(overrideSpns));

            LogUtil.log(LogLevel.VERBOSE, "Configuration saved to Burp persistence");
        } catch (Exception e) {
            LogUtil.alertAndLog(LogLevel.NORMAL, "Failed to save configuration: " + e.getMessage());
            LogUtil.logException(LogLevel.VERBOSE, e);
        }
    }

    private static PersistedList<String> toPersistedList(List<String> source) {
        PersistedList<String> pl = PersistedList.persistedStringList();
        pl.addAll(source);
        return pl;
    }

    /**
     * Load configuration from Burp's persisted extension data.
     */
    public void loadFromPersistedData(PersistedObject data) {
        try {
            Boolean b;
            String s;
            List<String> l;

            b = data.getBoolean(KEY_KERBEROS_ENABLED);
            if (b != null) kerberosEnabled = b;

            s = data.getString(KEY_DOMAIN);
            if (s != null) domain = s;

            s = data.getString(KEY_KDC);
            if (s != null) kdc = s;

            b = data.getBoolean(KEY_SAVE_PASSWORDS);
            if (b != null) savePasswords = b;

            s = data.getString(KEY_KRB5_CONF_PATH);
            if (s != null && !s.isEmpty()) krb5ConfPath = Paths.get(s);

            s = data.getString(KEY_AUTH_STRATEGY);
            if (s != null) {
                try { authenticationStrategy = AuthenticationStrategy.valueOf(s); } catch (IllegalArgumentException ignored) {}
            }

            b = data.getBoolean(KEY_EVERYTHING_IN_SCOPE);
            if (b != null) everythingInScope = b;

            b = data.getBoolean(KEY_WHOLE_DOMAIN_IN_SCOPE);
            if (b != null) wholeDomainInScope = b;

            b = data.getBoolean(KEY_IGNORE_NTLM);
            if (b != null) ignoreNTLMServers = b;

            b = data.getBoolean(KEY_PLAINHOST_EXPAND);
            if (b != null) plainhostExpand = b;

            l = data.getStringList(KEY_HOSTS_IN_SCOPE);
            if (l != null) { hostsInScope.clear(); hostsInScope.addAll(l); }

            s = data.getString(KEY_LOG_LEVEL);
            if (s != null) {
                try { logLevel = LogLevel.valueOf(s); } catch (IllegalArgumentException ignored) {}
            }

            s = data.getString(KEY_ALERT_LEVEL);
            if (s != null) {
                try { alertLevel = LogLevel.valueOf(s); } catch (IllegalArgumentException ignored) {}
            }

            l = data.getStringList(KEY_CUSTOM_SPNS);
            if (l != null) { customSpns.clear(); customSpns.addAll(l); }

            s = data.getString(KEY_CUSTOM_HEADER);
            if (s != null) customHeader = s;

            s = data.getString(KEY_DEFAULT_USERNAME);
            if (s != null) defaultUsername = s;

            // Users: deserialize flat list
            l = data.getStringList(KEY_USERS);
            if (l != null && l.size() >= 4) {
                users.clear();
                for (int i = 0; i + 3 < l.size(); i += 4) {
                    users.add(new String[]{ l.get(i), l.get(i + 1), l.get(i + 2), l.get(i + 3) });
                }
            }

            // SPN overrides: parallel lists
            List<String> overrideHosts = data.getStringList(KEY_SPN_OVERRIDES_HOSTS);
            List<String> overrideSpns = data.getStringList(KEY_SPN_OVERRIDES_SPNS);
            if (overrideHosts != null && overrideSpns != null) {
                spnOverrides.clear();
                for (int i = 0; i < overrideHosts.size() && i < overrideSpns.size(); i++) {
                    spnOverrides.put(overrideHosts.get(i), overrideSpns.get(i));
                }
            }

            // Apply domain/KDC system properties if set
            if (domain != null && !domain.isEmpty()) {
                System.setProperty("java.security.krb5.realm", domain.toUpperCase());
                if (kdc != null && !kdc.isEmpty()) {
                    System.setProperty("java.security.krb5.kdc", kdc);
                }
            }
            if (krb5ConfPath != null) {
                System.setProperty("java.security.krb5.conf", krb5ConfPath.toString());
            }

            LogUtil.log(LogLevel.VERBOSE, "Configuration loaded from Burp persistence");
        } catch (Exception e) {
            LogUtil.alertAndLog(LogLevel.NORMAL, "Failed to load configuration: " + e.getMessage());
            LogUtil.logException(LogLevel.VERBOSE, e);
        }
    }

}
