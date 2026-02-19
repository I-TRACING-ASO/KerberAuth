package kerberauth.cache;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import java.util.regex.Pattern;

/**
 * Central, thread-safe cache manager for the extension.
 *
 * Holds working sets, SPN mappings, failure lists and a ContextCache for per-(user,spn,host) contexts.
 */
public class CacheManager {

    // Single-thread scheduled executor for cleanup tasks
    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "kerberauth-cache-cleaner");
        t.setDaemon(true);
        return t;
    });

    // --- core caches (concurrent) ---
    private final Set<String> workingSet = ConcurrentHashMap.newKeySet(); // successful SPNs/hosts
    private final ConcurrentMap<String, String> hostnameToSpnMap = new ConcurrentHashMap<>(); // host -> spn
    private final Set<String> failedSpns = ConcurrentHashMap.newKeySet(); // SPNs that failed globally
    private final ConcurrentMap<String, CopyOnWriteArrayList<String>> failedSpnsForHost = new ConcurrentHashMap<>();
    private final Set<String> hostnamesWithUnknownSpn = ConcurrentHashMap.newKeySet();

    private final ContextCache contextCache = new ContextCache();

    // scope pattern cache
    private final ConcurrentMap<String, Pattern> scopeStringRegexpMap = new ConcurrentHashMap<>();



    // default retention durations
    private volatile long workingSetRetentionSeconds = 900; // 15 minutes window for "working" freshness

    // Map to hold timestamps for workingSet entries for TTL-based eviction
    private final ConcurrentMap<String, Instant> workingSetTimestamps = new ConcurrentHashMap<>();

    // Singleton holder
    private static class Holder {
        private static final CacheManager INSTANCE = new CacheManager();
    }

    public static CacheManager getInstance() {
        return Holder.INSTANCE;
    }

    private CacheManager() {
        // schedule periodic cleanup (every 60 seconds)
        scheduler.scheduleAtFixedRate(this::cleanup, 60, 60, TimeUnit.SECONDS);
    }

    // ------------------------
    // Working set helpers
    // ------------------------

    /** Mark a key (host or spn) as working now. */
    public void markWorking(String key) {
        if (key == null) return;
        workingSet.add(key);
        workingSetTimestamps.put(key, Instant.now());
    }

    /** Check if key is in the working set and still fresh. */
    public boolean isWorking(String key) {
        if (key == null) return false;
        Instant ts = workingSetTimestamps.get(key);
        if (ts == null) return false;
        return Instant.now().isBefore(ts.plusSeconds(workingSetRetentionSeconds));
    }

    // ------------------------
    // hostname -> SPN map
    // ------------------------

    public void putHostnameToSpn(String hostname, String spn) {
        if (hostname == null || spn == null) return;
        hostnameToSpnMap.put(hostname, spn);
    }

    public Optional<String> getSpnForHostname(String hostname) {
        return Optional.ofNullable(hostnameToSpnMap.get(hostname));
    }

    public void removeHostnameSpn(String hostname) {
        hostnameToSpnMap.remove(hostname);
    }

    // ------------------------
    // failed SPN handling
    // ------------------------

    public void markSpnFailed(String spn) {
        if (spn == null) return;
        failedSpns.add(spn);
    }

    public boolean isSpnFailed(String spn) {
        return spn != null && failedSpns.contains(spn);
    }

    public void markSpnFailedForHost(String hostname, String spn) {
        if (hostname == null || spn == null) return;
        failedSpnsForHost.computeIfAbsent(hostname, h -> new CopyOnWriteArrayList<>()).add(spn);
    }

    public List<String> getFailedSpnsForHost(String hostname) {
        return failedSpnsForHost.getOrDefault(hostname, new CopyOnWriteArrayList<>());
    }

    // ------------------------
    // unknown SPN hosts
    // ------------------------

    public void markHostUnknownSpn(String hostname) {
        if (hostname == null) return;
        hostnamesWithUnknownSpn.add(hostname);
    }

    public boolean isHostUnknownSpn(String hostname) {
        return hostname != null && hostnamesWithUnknownSpn.contains(hostname);
    }

    public void clearHostUnknownSpn(String hostname) {
        hostnamesWithUnknownSpn.remove(hostname);
    }

    // ------------------------
    // context cache delegation
    // ------------------------

    public ContextCache getContextCache() {
        return contextCache;
    }

    // ------------------------
    // scope regexp cache
    // ------------------------

    public Pattern getOrCompileScopePattern(String patternStr) {
        return scopeStringRegexpMap.computeIfAbsent(patternStr, p -> Pattern.compile(p, Pattern.CASE_INSENSITIVE));
    }



    // ------------------------
    // cleanup & lifecycle
    // ------------------------

    /** Periodic cleanup task to evict expired context entries and stale workingSet members. */
    private void cleanup() {
        try {
            // cleanup context cache
            contextCache.cleanupExpiredEntries();

            // cleanup workingSet by timestamps
            Instant now = Instant.now();
            for (Map.Entry<String, Instant> e : workingSetTimestamps.entrySet()) {
                if (now.isAfter(e.getValue().plusSeconds(workingSetRetentionSeconds))) {
                    String key = e.getKey();
                    workingSetTimestamps.remove(key);
                    workingSet.remove(key);
                }
            }

            // Optionally, cleanup failedSpnsForHost entries older than some threshold (not implemented)
        } catch (Throwable t) {
            kerberauth.util.LogUtil.log(
                kerberauth.config.Config.LogLevel.NORMAL,
                "Cache cleanup error: " + t.getMessage());
        }
    }

    /** Shut down the scheduler (call on extension unload). */
    public void shutdown() {
        scheduler.shutdownNow();
    }

    /** Clear all caches (call on domain change or state reset). */
    public void clearAll() {
        workingSet.clear();
        workingSetTimestamps.clear();
        hostnameToSpnMap.clear();
        failedSpns.clear();
        failedSpnsForHost.clear();
        hostnamesWithUnknownSpn.clear();
        contextCache.cleanupExpiredEntries();
        scopeStringRegexpMap.clear();
    }

    // ------------------------
    // Debug / dump helpers
    // ------------------------

    public String dumpStatus() {
        StringBuilder sb = new StringBuilder();
        sb.append("workingSet: ").append(workingSetTimestamps.keySet()).append("\n");
        sb.append("hostnameToSpnMap: ").append(hostnameToSpnMap).append("\n");
        sb.append("failedSpns: ").append(failedSpns).append("\n");
        sb.append("failedSpnsForHost: ").append(failedSpnsForHost).append("\n");
        sb.append("hostnamesWithUnknownSpn: ").append(hostnamesWithUnknownSpn).append("\n");
        sb.append("contextCache.size: ").append(contextCache.size()).append("\n");

        return sb.toString();
    }
}
