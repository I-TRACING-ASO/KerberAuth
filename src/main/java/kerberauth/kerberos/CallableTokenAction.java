package kerberauth.kerberos;

import java.util.concurrent.Callable;
import java.util.List;
import java.util.Base64;

import org.ietf.jgss.*;
import com.sun.security.jgss.ExtendedGSSContext;

import kerberauth.cache.CacheManager;
import kerberauth.config.Config;
import kerberauth.util.LogUtil;

public class CallableTokenAction implements Callable<ContextTokenSpnTriple> {
    private static final Oid SPNEGO_MECH_OID;
    private static final Oid KRB5_PRINCIPAL_NAME_OID;

    static {
        try {
            SPNEGO_MECH_OID = new Oid("1.3.6.1.5.5.2");
            KRB5_PRINCIPAL_NAME_OID = new Oid("1.2.840.113554.1.2.2.1");
        } catch (GSSException e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    private List<String> spns;

    public CallableTokenAction(List<String> spns) {
        this.spns = spns;
    }

    @Override
    public ContextTokenSpnTriple call() throws TGTExpiredException {

        String encodedToken = "";
        GSSContext context = null;
        GSSManager manager = GSSManager.getInstance();
        
        for( String spn : spns)
        {
            LogUtil.log(Config.LogLevel.VERBOSE, "SPN to try: " + spn);
        }

        for (String spn : spns) {
            LogUtil.log(Config.LogLevel.VERBOSE, "Trying SPN: " + spn);
            try {
                GSSName gssServerName = createServerName(manager, spn);

                context = manager.createContext(gssServerName, SPNEGO_MECH_OID, null, GSSCredential.INDEFINITE_LIFETIME);
                
                if (context instanceof ExtendedGSSContext extendedContext) {
                    extendedContext.requestDelegPolicy(true);
                }

                byte spnegoToken[] = new byte[0];
                spnegoToken = context.initSecContext(spnegoToken, 0, spnegoToken.length);
                encodedToken = Base64.getEncoder().encodeToString(spnegoToken);

                return new ContextTokenSpnTriple(context, spn, encodedToken);
            } catch (Exception e) {
                if (e.getMessage().contains("Server not found in Kerberos database")) {
                    LogUtil.alertAndLog(
                            Config.LogLevel.NORMAL,
                            String.format("Failed to acquire service ticket for %s - service name not recognised by KDC", spn));
                    CacheManager.getInstance().markSpnFailed(spn);
                    continue;
                } else if (e.getMessage().contains("Message stream modified")) {
                    LogUtil.alertAndLog(
                            Config.LogLevel.NORMAL,
                            String.format("Failed to acquire service ticket for %s - host is in a different realm?", spn));
                    CacheManager.getInstance().markSpnFailed(spn);
                    continue;
                } else if (e.getMessage().contains("Failed to find any Kerberos tgt")
                        || e.getMessage().contains("Ticket expired")) {
                    LogUtil.alertAndLog(
                            Config.LogLevel.NORMAL,
                            String.format("Failed to acquire token for service %s, TGT has expired? Trying to get a new one...", spn));
                    throw new TGTExpiredException("TGT Expired");
                } else {
                    LogUtil.alertAndLog(
                            Config.LogLevel.NORMAL,
                            String.format("Failed to acquire token for service %s, error message was %s", spn, e.getMessage()));
                    LogUtil.logException(Config.LogLevel.VERBOSE, e);
                }
            }
        }

        return null;
    }

    private GSSName createServerName(GSSManager manager, String spn) throws GSSException {
        // Most callers provide a Kerberos principal form (HTTP/host@REALM).
        if (spn != null && spn.contains("/")) {
            try {
                return manager.createName(spn, KRB5_PRINCIPAL_NAME_OID);
            } catch (GSSException e) {
                LogUtil.log(Config.LogLevel.VERBOSE,
                    "Failed KRB5 principal name parsing for SPN " + spn + ", trying host-based fallback");
            }
        }

        String hostBased = toHostBasedService(spn);
        return manager.createName(hostBased, GSSName.NT_HOSTBASED_SERVICE);
    }

    private String toHostBasedService(String spn) {
        if (spn == null) {
            return "";
        }

        String withoutRealm = spn;
        int realmSep = withoutRealm.indexOf('@');
        if (realmSep > 0) {
            withoutRealm = withoutRealm.substring(0, realmSep);
        }

        int serviceSep = withoutRealm.indexOf('/');
        if (serviceSep > 0 && serviceSep < withoutRealm.length() - 1) {
            String service = withoutRealm.substring(0, serviceSep);
            String host = withoutRealm.substring(serviceSep + 1);
            return service + "@" + host;
        }

        return withoutRealm;
    }
}