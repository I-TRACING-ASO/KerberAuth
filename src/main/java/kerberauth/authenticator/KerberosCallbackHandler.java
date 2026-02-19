package kerberauth.authenticator;

import kerberauth.model.UserEntry;
import kerberauth.util.LogUtil;
import kerberauth.config.Config;

import javax.security.auth.callback.*;

/**
 * CallbackHandler for providing Kerberos credentials during JAAS login.
 */
public class KerberosCallbackHandler implements CallbackHandler {
    
    private final UserEntry user;
    
    public KerberosCallbackHandler(UserEntry user) {
        this.user = user;
    }
    
    @Override
    public void handle(Callback[] callbacks) throws UnsupportedCallbackException {
        for (Callback callback : callbacks) {
            if (callback instanceof NameCallback) {
                NameCallback nc = (NameCallback) callback;
                nc.setName(user.getPrincipal());
                LogUtil.log(Config.LogLevel.VERBOSE, 
                    "Provided principal: " + user.getPrincipal());
                
            } else if (callback instanceof PasswordCallback) {
                PasswordCallback pc = (PasswordCallback) callback;
                pc.setPassword(user.getPassword());
                LogUtil.log(Config.LogLevel.VERBOSE, 
                    "Provided password for user: " + user.getUsername());
                
            } else {
                throw new UnsupportedCallbackException(callback, 
                    "Unsupported callback: " + callback.getClass().getName());
            }
        }
    }
}