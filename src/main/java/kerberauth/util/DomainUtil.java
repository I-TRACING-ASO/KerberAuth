package kerberauth.util;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import kerberauth.cache.CacheManager;
import kerberauth.config.Config;

public class DomainUtil {

    public static boolean checkHostnameRegexp(String input) {
        // http://stackoverflow.com/questions/1418423/the-hostname-regex
        String pattern = "^(?=.{1,255}$)[0-9A-Za-z](?:(?:[0-9A-Za-z]|-){0,61}[0-9A-Za-z])?(?:\\.[0-9A-Za-z](?:(?:[0-9A-Za-z]|-){0,61}[0-9A-Za-z])?)*\\.?$";
        Pattern r = Pattern.compile(pattern);
        Matcher m = r.matcher(input);
        return m.find();
    }

    public static boolean isMultiComponentHostname(String input) {
        return input.contains(".");
    }

    public static boolean isInScope(String hostname, Config config) {
        if (config.isEverythingInScope() 
            || (isPlainhostname(hostname) && config.isPlainhostExpand() && config.isWholeDomainInScope())
            || (config.isWholeDomainInScope() && hostname.toLowerCase().endsWith(config.getDomain().toLowerCase()))
        ) {
            return true;
        }

        for (String scopeEntry : config.getHostsInScope()) {
            Pattern pattern = getPatternForScopeString(scopeEntry);
            Matcher matcher = pattern.matcher(hostname);
            if (matcher.matches()) {
                return true;
            }
        }

        return false;
    }

    private static boolean isPlainhostname(String hostname) {
        return (hostname.length() > 0) && (hostname.indexOf('.') == -1) && (hostname.indexOf('@') == -1);
    }

    private static Pattern getPatternForScopeString(String scopeEntry) {
        String regexString = scopeEntry.replace( ".", "\\."); // dots in hostnames should be treated as literal dots
        regexString = regexString.replace( "-", "\\-"); // same for hyphens
        regexString = regexString.replace( "*", ".*"); // our "regexp" says that * matches zero or more characters. Needs to be ".*"
        regexString = regexString.replace( "?", "[^.]"); // question mark is to match anything but a dot
            
        Pattern pattern = Pattern.compile(regexString, Pattern.CASE_INSENSITIVE); 
        return pattern;
    }

    /**
     * Helper method to build a SPN string for a host when the domain/realm is known.
     *
     * @param hostname the hostname of the service
     * @param realm    the Kerberos realm
     * @return SPN string (e.g., "HTTP/hostname@REALM")
     */
    public static String buildSpn(String hostname, String realm) {
        return "HTTP/" + hostname + "@" + realm;
    }

    /**
     * Resolve an ordered list of candidate SPNs for a given hostname.
     * 
     * Resolution order:
     * 1. SPN overrides from Config (user-defined host→SPN mappings)
     * 2. SPN hints from CacheManager (e.g. from krb5.conf appdefaults)
     * 3. Cached hostname→SPN mapping (from previous successful authentication)
     * 4. DNS CNAME resolution to find the canonical hostname
     * 5. Plain hostname expansion (append domain if configured)
     * 6. Build multiple SPN candidates with/without realm
     * 7. Filter out known-failed SPNs
     *
     * @param hostname the target hostname from the HTTP request
     * @return ordered list of SPNs to try
     */
    public static List<String> resolveSpns(String hostname) {
        Config config = Config.getInstance();
        CacheManager cache = CacheManager.getInstance();
        String realm = config.getRealmName();
        List<String> candidates = new ArrayList<>();

        // 1. Check SPN overrides / hints (user-configured in CustomSPNPanel)
        //    Supports Berserko-style format: "target.host" or "target.host@REALM"
        //    as well as full SPN format: "HTTP/target.host@REALM"
        for (Map.Entry<String, String> entry : config.getSpnOverrides().entrySet()) {
            if (hostname.equalsIgnoreCase(entry.getKey())) {
                String spn = normalizeSpn(entry.getValue(), realm);
                LogUtil.log(Config.LogLevel.VERBOSE, "SPN override found for " + hostname + ": " + spn);
                candidates.add(spn);
                return candidates; // override is authoritative
            }
        }

        // 2. Check cached hostname→SPN mapping
        Optional<String> cachedSpn = cache.getSpnForHostname(hostname);
        if (cachedSpn.isPresent()) {
            LogUtil.log(Config.LogLevel.VERBOSE, "Cached SPN for " + hostname + ": " + cachedSpn.get());
            candidates.add(cachedSpn.get());
            return candidates;
        }

        // 3. Resolve CNAME to get canonical hostname
        String canonicalHostname = resolveCname(hostname);

        // 4. Plain hostname expansion
        String expandedHostname = hostname;
        if (isPlainhostname(hostname) && config.isPlainhostExpand()) {
            String domain = config.getDomain();
            if (domain != null && !domain.isEmpty()) {
                expandedHostname = hostname + "." + domain;
                LogUtil.log(Config.LogLevel.VERBOSE, "Expanded plain hostname: " + hostname + " -> " + expandedHostname);
            }
        }

        // 5. Build candidate SPNs (most specific first)
        // If CNAME differs from original hostname, try CNAME first
        if (canonicalHostname != null && !canonicalHostname.equalsIgnoreCase(hostname)
                && !canonicalHostname.equalsIgnoreCase(expandedHostname)) {
            addSpnCandidate(candidates, canonicalHostname, realm);
        }

        // Try expanded hostname (or original if not expanded)
        if (!expandedHostname.equalsIgnoreCase(hostname)) {
            addSpnCandidate(candidates, expandedHostname, realm);
        }

        // Try original hostname
        addSpnCandidate(candidates, hostname, realm);

        // 6. Filter out known-failed SPNs and per-host failures
        List<String> failedForHost = cache.getFailedSpnsForHost(hostname);
        candidates.removeIf(spn -> cache.isSpnFailed(spn) || failedForHost.contains(spn));

        // If all candidates were filtered out, re-add the primary one as last resort
        if (candidates.isEmpty()) {
            candidates.add(buildSpn(expandedHostname, realm));
            LogUtil.log(Config.LogLevel.VERBOSE, "All SPNs were filtered as failed for " + hostname + ", retrying primary");
        }

        LogUtil.log(Config.LogLevel.VERBOSE, "SPN candidates for " + hostname + ": " + candidates);
        return candidates;
    }

    /**
     * Normalize an SPN value from Config overrides.
     * Supports:
     * - Full SPN: "HTTP/host@REALM" → as-is
     * - Berserko-style with realm: "host@REALM" → "HTTP/host@REALM"
     * - Berserko-style without realm: "host" → "HTTP/host@REALM"
     */
    private static String normalizeSpn(String value, String realm) {
        if (value.toUpperCase().startsWith("HTTP/")) {
            return value;
        }
        if (value.contains("@")) {
            return "HTTP/" + value;
        }
        return buildSpn(value, realm);
    }

    /**
     * Add SPN candidates for a resolved hostname: with realm and without realm.
     */
    private static void addSpnCandidate(List<String> candidates, String host, String realm) {
        String spnWithRealm = buildSpn(host, realm);
        if (!candidates.contains(spnWithRealm)) {
            candidates.add(spnWithRealm);
        }
    }

    /**
     * Resolve DNS CNAME for a hostname. Returns the canonical name or null if
     * the hostname doesn't have a CNAME or resolution fails.
     */
    static String resolveCname(String hostname) {
        try {
            InetAddress addr = InetAddress.getByName(hostname);
            String canonical = addr.getCanonicalHostName();
            // getCanonicalHostName may return the IP if reverse DNS fails — ignore it
            if (canonical != null && !canonical.equals(addr.getHostAddress())
                    && !canonical.equalsIgnoreCase(hostname)) {
                LogUtil.log(Config.LogLevel.VERBOSE, "CNAME resolved: " + hostname + " -> " + canonical);
                // Remove trailing dot if present
                if (canonical.endsWith(".")) {
                    canonical = canonical.substring(0, canonical.length() - 1);
                }
                return canonical;
            }
        } catch (UnknownHostException e) {
            LogUtil.log(Config.LogLevel.VERBOSE, "DNS resolution failed for " + hostname + ": " + e.getMessage());
        }
        return null;
    }
}
