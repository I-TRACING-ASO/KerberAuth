package kerberauth.kerberos;

import kerberauth.config.Config;
import kerberauth.model.UserEntry;

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.*;
import java.util.HashMap;
import java.util.Map;

public class LoginContextFactory {
    
    private static final String JAAS_LOGIN_NAME = "KerberAuthLogin"; 
    private static final Configuration SHARED_CONFIG = new KerberosConfiguration();

    public static LoginContext createLoginContext(UserEntry user, CallbackHandler handler) throws LoginException {
        return new LoginContext(JAAS_LOGIN_NAME, null, handler, SHARED_CONFIG);
    }

    private static class KerberosConfiguration extends Configuration {
        @Override
        public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
            Map<String, String> options = new HashMap<>();

            options.put("refreshKrb5Config", "true");
            options.put("doNotPrompt", "false");
            options.put("useTicketCache", "false");
            options.put("debug", Config.getInstance().getLogLevel().equals(Config.LogLevel.VERBOSE) ? "true" : "false");

            return new AppConfigurationEntry[] {
                new AppConfigurationEntry(
                        "com.sun.security.auth.module.Krb5LoginModule",
                        AppConfigurationEntry.LoginModuleControlFlag.REQUIRED,
                        options
                )
            };
        }

        @Override
        public void refresh() {
            // ignored
        }
    }
}
