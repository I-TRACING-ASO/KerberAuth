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
                Oid spnegoMechOid = new Oid("1.3.6.1.5.5.2");
                GSSName gssServerName = manager.createName(spn, GSSName.NT_HOSTBASED_SERVICE);

                context = manager.createContext(gssServerName, spnegoMechOid, null, GSSCredential.INDEFINITE_LIFETIME);
                
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
}