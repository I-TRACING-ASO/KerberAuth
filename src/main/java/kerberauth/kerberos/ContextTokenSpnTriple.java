package kerberauth.kerberos;

import org.ietf.jgss.GSSContext;

public class ContextTokenSpnTriple {
    private GSSContext context;
    private String token;
    private String spn;

    public ContextTokenSpnTriple(GSSContext c, String s, String t) {
        context = c;
        token = t;
        spn = s;
    }

    public GSSContext getContext() {
        return context;
    }

    public String getToken() {
        return token;
    }

    public String getSpn() {
        return spn;
    }

    public boolean isExpired() {
        if (context == null || !context.isEstablished()) {
            return true;
        }

        int lifetime = context.getLifetime();
        return lifetime != GSSContext.INDEFINITE_LIFETIME && lifetime <= 0;
    }
}