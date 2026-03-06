package kerberauth.ui;

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;

import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;

import kerberauth.config.Config;
import kerberauth.KerberAuthExtension;

import java.util.ArrayList;
import java.util.List;

/**
 * Panel for general / master settings of the Kerberos authentication extension.
 */
public class MasterSettingsPanel extends JPanel {

    public interface MasterSwitchListener {
        void onMasterSwitchChanged(boolean enabled);
        void onRestoreDefaults();
    }

    private final JCheckBox masterSwitchCheckBox = new JCheckBox("Enable Kerberos authentication");
    private final JLabel versionLabel = new JLabel(KerberAuthExtension.EXTENSION_NAME + " version " + KerberAuthExtension.EXTENSION_VERSION);
    private final JButton restoreDefaultsButton = new JButton("Restore default settings");
    private final JButton clearStateButton = new JButton("Clear Kerberos state");
    private final JButton logTicketsButton = new JButton("Write tickets to log");
    private final List<MasterSwitchListener> listeners = new ArrayList<>();

    public MasterSettingsPanel() {
        super(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.anchor = GridBagConstraints.WEST;

        // MAIN PANEL LAYOUT

        gbc.gridwidth = 5;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        gbc.weighty = 0.0;
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.gridwidth = 1;
        this.add(masterSwitchCheckBox, gbc);
        gbc.fill = GridBagConstraints.NONE;
        gbc.weightx = 0.0;
        gbc.weighty = 0.0;
        gbc.gridx = 1;
        gbc.gridy = 0;
        this.add(logTicketsButton, gbc);
        gbc.fill = GridBagConstraints.NONE;
        gbc.weightx = 0.0;
        gbc.weighty = 0.0;
        gbc.gridx = 2;
        gbc.gridy = 0;
        this.add(restoreDefaultsButton, gbc);
        gbc.fill = GridBagConstraints.NONE;
        gbc.weightx = 0.0;
        gbc.weighty = 0.0;
        gbc.gridx = 3;
        gbc.gridy = 0;
        this.add(clearStateButton, gbc);
        gbc.fill = GridBagConstraints.NONE;
        gbc.weightx = 0.0;
        gbc.weighty = 0.0;
        gbc.gridx = 4;
        gbc.gridy = 0;
        this.add(versionLabel, gbc);
        
        // ACTION LISTENERS
        masterSwitchCheckBox.addActionListener(e -> {
            boolean enabled = masterSwitchCheckBox.isSelected();
            Config.getInstance().setKerberosEnabled(enabled);
            for (MasterSwitchListener l : listeners) l.onMasterSwitchChanged(enabled);
        });

        restoreDefaultsButton.addActionListener(e -> {
            Config.getInstance().restoreDefaults();
            masterSwitchCheckBox.setSelected(false);
            for (MasterSwitchListener l : listeners) l.onRestoreDefaults();
        });

        clearStateButton.addActionListener(e -> {
            int choice = JOptionPane.showConfirmDialog(
                this,
                "This will clear Kerberos tickets/session state for configured users.\n\nContinue?",
                "Confirm clear Kerberos state",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.WARNING_MESSAGE
            );

            if (choice == JOptionPane.YES_OPTION) {
                Config.getInstance().clearKerberosState();
            }
        });

        logTicketsButton.addActionListener(e -> {
            Config.getInstance().logKerberosTickets();
        });
    }

    public void addListener(MasterSwitchListener listener) {
        listeners.add(listener);
    }

    public boolean isMasterEnabled() {
        return masterSwitchCheckBox.isSelected();
    }

    /**
     * Load values from Config singleton into the UI fields.
     */
    public void loadFromConfig() {
        Config config = Config.getInstance();
        masterSwitchCheckBox.setSelected(config.isKerberosEnabled());
    }
}
