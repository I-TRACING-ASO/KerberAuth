package kerberauth.ui;

import kerberauth.KerberAuthExtension;
import kerberauth.config.Config;

import javax.swing.*;
import java.awt.*;

/**
 * Panel for configuring the Kerberos authentication strategy.
 *
 * This panel allows the user to choose how the extension applies Kerberos authentication.
 * For example:
 *  - Always use default user
 *  - Select user by header
 *  - Prompt per scope
 */
public class AuthenticationStrategySettingsPanel extends JPanel {

    private final JComboBox<String> strategyCombo;
    private boolean loading = false;

    public AuthenticationStrategySettingsPanel() {
        super(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;

        // Combo box for authentication strategy
        gbc.gridx = 0;
        gbc.gridy = 0;
        this.add(new JLabel("Authentication Strategy:"), gbc);

        strategyCombo = new JComboBox<>(new String[]{
                "Reactive - Add auth on 401 Negotiate",
                "Proactive - Add auth to all in-scope requests",
                "Proactive (401) - Add auth after first 401 Negotiate"
        });
        gbc.gridx = 1;
        gbc.weightx = 1.0;
        this.add(strategyCombo, gbc);

        strategyCombo.addActionListener(e -> { if (!loading) saveToConfig(); });
    }

    /**
     * Load values from Config singleton into the UI fields.
     */
    public void loadFromConfig() {
        loading = true;
        try {
            Config config = Config.getInstance();

            // Map authentication strategy to combo box index
            Config.AuthenticationStrategy strategy = config.getAuthenticationStrategy();
            switch (strategy) {
                case REACTIVE:
                    strategyCombo.setSelectedIndex(0);
                    break;
                case PROACTIVE:
                    strategyCombo.setSelectedIndex(1);
                    break;
                case PROACTIVE_401:
                    strategyCombo.setSelectedIndex(2);
                    break;
            }
        } finally {
            loading = false;
        }
    }

    /**
     * Save values from UI fields into Config singleton.
     */
    public void saveToConfig() {
        Config config = Config.getInstance();
        
        // Map combo box index to authentication strategy
        int selectedIndex = strategyCombo.getSelectedIndex();
        switch (selectedIndex) {
            case 0:
                config.setAuthenticationStrategy(Config.AuthenticationStrategy.REACTIVE);
                break;
            case 1:
                config.setAuthenticationStrategy(Config.AuthenticationStrategy.PROACTIVE);
                break;
            case 2:
                config.setAuthenticationStrategy(Config.AuthenticationStrategy.PROACTIVE_401);
                break;
        }

        if (config.getAuthenticationStrategy() == Config.AuthenticationStrategy.PROACTIVE
                && config.isEverythingInScope()) {
            JOptionPane.showMessageDialog(KerberAuthExtension.suiteFrame(),
                "Combining 'Proactive' strategy with 'All hosts in scope' is not recommended.\n"
                + "This will cause Kerberos authentication attempts to every host passing through Burp,\n"
                + "which may cause performance issues and leak information to the KDC.",
                "Warning", JOptionPane.WARNING_MESSAGE);
        }
    }
}
