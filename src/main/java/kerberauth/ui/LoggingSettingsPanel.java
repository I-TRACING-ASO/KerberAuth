package kerberauth.ui;

import javax.swing.*;
import java.awt.*;

import kerberauth.config.Config;

/**
 * Panel for configuring and displaying logging information for the extension.
 *
 * This panel can be used to:
 *  - choose the logging verbosity (none/normal/verbose)
 *  - choose the alert verbosity (none/normal/verbose)
 */
public class LoggingSettingsPanel extends JPanel {

    private final JComboBox<String> logLevelCombo;
    private final JComboBox<String> alertLevelCombo;
    private boolean loading = false;

    public LoggingSettingsPanel() {
        super(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;

        // Log level selector
        gbc.gridx = 0;
        gbc.gridy = 0;
        this.add(new JLabel("Log level:"), gbc);

        logLevelCombo = new JComboBox<>(new String[]{
                "None","Normal","Verbose"
        });
        gbc.gridx = 1;
        this.add(logLevelCombo, gbc);

        // Alert level selector
        gbc.gridx = 0;
        gbc.gridy++;
        this.add(new JLabel("Alert level:"), gbc);

        alertLevelCombo = new JComboBox<>(new String[]{
                "None","Normal","Verbose"
        });
        gbc.gridx = 1;
        this.add(alertLevelCombo, gbc);

        logLevelCombo.addActionListener(e -> { if (!loading) saveToConfig(); });
        alertLevelCombo.addActionListener(e -> { if (!loading) saveToConfig(); });
    }

    /**
     * Load values from Config singleton into the UI fields.
     */
    public void loadFromConfig() {
        loading = true;
        try {
            Config config = Config.getInstance();
            logLevelCombo.setSelectedItem(config.getLogLevel().name().substring(0, 1)
                    + config.getLogLevel().name().substring(1).toLowerCase());
            alertLevelCombo.setSelectedItem(config.getAlertLevel().name().substring(0, 1)
                    + config.getAlertLevel().name().substring(1).toLowerCase());
        } finally {
            loading = false;
        }
    }

    public void saveToConfig() {
        Config config = Config.getInstance();
        String log = (String) logLevelCombo.getSelectedItem();
        String alert = (String) alertLevelCombo.getSelectedItem();
        if (log != null) config.setLogLevel(Config.LogLevel.valueOf(log.toUpperCase()));
        if (alert != null) config.setAlertLevel(Config.LogLevel.valueOf(alert.toUpperCase()));
    }
}
