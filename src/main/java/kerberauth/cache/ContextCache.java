package kerberauth.cache;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import kerberauth.kerberos.ContextTokenSpnTriple;

public class ContextCache {
    private final Map<String, ContextTokenSpnTriple> contextMap;
    private final int maxCache = 1000;

    public ContextCache() {
        contextMap = new ConcurrentHashMap<>();
    }

    private static String cacheKey(String username, String spn) {
        return username + "|" + spn;
    }

    public boolean isEmpty() {
        return contextMap.isEmpty();
    }

    public void addToCache(String username, ContextTokenSpnTriple ctst) {
        if (username == null || ctst.getSpn() == null) return;
        if (contextMap.size() < maxCache) {
            contextMap.put(cacheKey(username, ctst.getSpn()), ctst);
        }
    }

    public void removeFromCache(String username, String spn) {
        if (username != null && spn != null) {
            contextMap.remove(cacheKey(username, spn));
        }
    }

    public ContextTokenSpnTriple getFromCache(String username, String spn) {
        if (username == null || spn == null) return null;
        ContextTokenSpnTriple ctst = contextMap.get(cacheKey(username, spn));
        if (ctst != null && ctst.isExpired()) {
            contextMap.remove(cacheKey(username, spn));
            return null;
        }
        return ctst;
    }

    public void cleanupExpiredEntries() {
        contextMap.entrySet().removeIf(entry -> entry.getValue().isExpired());
    }

    public int size() {
        return contextMap.size();
    }
}
