package kerberauth;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

import java.awt.Frame;

import kerberauth.cache.CacheManager;
import kerberauth.kerberos.KerberosManager;
import kerberauth.ui.KerberAuthTab;
import kerberauth.http.KerberosHttpHandler;
import kerberauth.manager.UserManager;
import kerberauth.util.LogUtil;
import kerberauth.config.Config;

public class KerberAuthExtension implements BurpExtension {

    public static final String EXTENSION_NAME = "KerberAuth";
    public static final String EXTENSION_VERSION = resolveVersion();
    public static MontoyaApi api;
    
    private static String origUseSubjectCredsOnly;
    private static String origKrb5Conf;
    private static String origKrb5Realm;
    private static String origKrb5Kdc;

    @Override
    public void initialize(MontoyaApi montoyaApi) {
        api = montoyaApi;
        api.extension().setName(EXTENSION_NAME);

        // Save original System properties so they can be restored on unload
        origUseSubjectCredsOnly = System.getProperty("javax.security.auth.useSubjectCredsOnly");
        origKrb5Conf = System.getProperty("java.security.krb5.conf");
        origKrb5Realm = System.getProperty("java.security.krb5.realm");
        origKrb5Kdc = System.getProperty("java.security.krb5.kdc");

        // Ensure GSS uses only the Subject credentials (no implicit re-acquisition)
        System.setProperty("javax.security.auth.useSubjectCredsOnly", "true");

        // Load persisted configuration
        Config.getInstance().loadFromPersistedData(api.persistence().extensionData());

        UserManager.getInstance().initialize();

        KerberAuthTab tab = new KerberAuthTab();
        api.userInterface().registerSuiteTab(EXTENSION_NAME, tab);
        api.http().registerHttpHandler(new KerberosHttpHandler(api));

        api.extension().registerUnloadingHandler(() -> {
            LogUtil.log(Config.LogLevel.NORMAL, EXTENSION_NAME + " unloading...");
            tab.saveToConfig();
            Config.getInstance().saveToPersistedData(api.persistence().extensionData());
            KerberosManager.getInstance().logoutAll();
            CacheManager.getInstance().shutdown();

            // Restore original System properties
            restoreProperty("javax.security.auth.useSubjectCredsOnly", origUseSubjectCredsOnly);
            restoreProperty("java.security.krb5.conf", origKrb5Conf);
            restoreProperty("java.security.krb5.realm", origKrb5Realm);
            restoreProperty("java.security.krb5.kdc", origKrb5Kdc);

            LogUtil.log(Config.LogLevel.NORMAL, EXTENSION_NAME + " unloaded.");
        });

        api.logging().logToOutput(EXTENSION_NAME + " " + EXTENSION_VERSION + " extension loaded.");
    }

    private static void restoreProperty(String key, String originalValue) {
        if (originalValue == null) {
            System.clearProperty(key);
        } else {
            System.setProperty(key, originalValue);
        }
    }

    /**
     * Return the Burp Suite main frame, suitable as parent for JOptionPane dialogs.
     */
    public static Frame suiteFrame() {
        return api.userInterface().swingUtils().suiteFrame();
    }

    private static String resolveVersion() {
        String version = KerberAuthExtension.class.getPackage().getImplementationVersion();
        return (version != null && !version.isBlank()) ? version : "dev";
    }
}