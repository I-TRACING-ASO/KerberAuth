package kerberauth.ui;

import javax.swing.*;

import kerberauth.config.Config;
import kerberauth.util.LogUtil;

import java.awt.*;

/**
 * Top-level Burp tab that aggregates all configuration sub-panels.
 *
 * Each logical section of the original monolithic UI is split into a dedicated
 * JPanel subclass:
 *  - MasterSettingsPanel
 *  - DomainSettingsPanel
 *  - CredentialsSettingsPanel
 *  - DelegationSettingsPanel
 *  - AuthenticationStrategySettingsPanel
 *  - ScopeSettingsPanel
 *  - CustomSPNPanel
 *  - LoggingSettingsPanel
 *
 * This class only composes those panels into a scrollable tab suitable for
 * injection into Burp's UI. Actual business logic (listeners, config binding,
 * persistence) should be implemented inside the individual panels or in a
 * controller that listens to their events.
 */
public class KerberAuthTab extends JPanel {

    private final MasterSettingsPanel masterSettingsPanel;
    private final DomainSettingsPanel domainSettingsPanel;
    private final CredentialsSettingsPanel credentialsSettingsPanel;
    private final DelegationSettingsPanel delegationSettingsPanel;
    private final AuthenticationStrategySettingsPanel authenticationStrategySettingsPanel;
    private final ScopeSettingsPanel scopeSettingsPanel;
    private final CustomSPNPanel customSPNPanel;
    private final LoggingSettingsPanel loggingSettingsPanel;

    private final JPanel mainPanel;
    private final JScrollPane scrollPane;

    /** Sub-panels that should be grayed out when master switch is off. */
    private final JComponent[] configPanels;

    /**
     * Construct the Kerberos Auth tab and assemble all sub-panels.
     */
    public KerberAuthTab() {
        super(new BorderLayout());

        // create sub-panels (these classes must extend JPanel and provide their own layout)
        masterSettingsPanel = new MasterSettingsPanel();
        domainSettingsPanel = new DomainSettingsPanel();
        credentialsSettingsPanel = new CredentialsSettingsPanel();
        delegationSettingsPanel = new DelegationSettingsPanel();
        authenticationStrategySettingsPanel = new AuthenticationStrategySettingsPanel();
        scopeSettingsPanel = new ScopeSettingsPanel();
        customSPNPanel = new CustomSPNPanel();
        loggingSettingsPanel = new LoggingSettingsPanel();

        configPanels = new JComponent[]{
                domainSettingsPanel, credentialsSettingsPanel, delegationSettingsPanel,
                authenticationStrategySettingsPanel, scopeSettingsPanel, customSPNPanel,
                loggingSettingsPanel
        };

        // Wire master switch listener
        masterSettingsPanel.addListener(new MasterSettingsPanel.MasterSwitchListener() {
            @Override
            public void onMasterSwitchChanged(boolean enabled) {
                setConfigPanelsEnabled(enabled);
            }

            @Override
            public void onRestoreDefaults() {
                loadFromConfig();
                setConfigPanelsEnabled(masterSettingsPanel.isMasterEnabled());
            }
        });

        // mainPanel holds the vertically stacked sections
        mainPanel = new JPanel(new GridBagLayout());

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(0, 0, 8, 0);

        // add master settings
        mainPanel.add(addPadding(masterSettingsPanel), gbc);
        gbc.gridy++;

        // domain settings
        mainPanel.add(wrapWithTitledBorder(addPadding(domainSettingsPanel), "Domain Settings"), gbc);
        gbc.gridy++;

        // credentials
        mainPanel.add(wrapWithTitledBorder(addPadding(credentialsSettingsPanel), "Domain Credentials"), gbc);
        gbc.gridy++;

        // delegation / krb5.conf
        mainPanel.add(wrapWithTitledBorder(addPadding(delegationSettingsPanel), "Delegation (krb5.conf)"), gbc);
        gbc.gridy++;

        // authentication strategy
        mainPanel.add(wrapWithTitledBorder(addPadding(authenticationStrategySettingsPanel), "Authentication Strategy"), gbc);
        gbc.gridy++;

        // scope
        mainPanel.add(wrapWithTitledBorder(addPadding(scopeSettingsPanel), "Scope"), gbc);
        gbc.gridy++;

        // custom SPN overrides
        mainPanel.add(wrapWithTitledBorder(addPadding(customSPNPanel), "Custom SPN Overrides"), gbc);
        gbc.gridy++;

        // logging
        mainPanel.add(wrapWithTitledBorder(addPadding(loggingSettingsPanel), "Logging"), gbc);
        gbc.gridy++;

        // filler to push content to top and allow vertical expansion
        gbc.fill = GridBagConstraints.BOTH;
        gbc.weighty = 1.0;
        JPanel filler = new JPanel();
        filler.setOpaque(false);
        mainPanel.add(filler, gbc);

        // make mainPanel scrollable for smaller windows
        scrollPane = new JScrollPane(mainPanel,
                JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,
                JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);

        this.add(scrollPane, BorderLayout.CENTER);

        // Load config into UI at construction time
        loadFromConfig();
        setConfigPanelsEnabled(masterSettingsPanel.isMasterEnabled());
    }

    /**
     * Utility to wrap a given panel with a titled border if it doesn't have one already.
     *
     * @param panel panel to wrap
     * @param title title for the border
     * @return the panel (possibly wrapped) ready to be added to the layout
     */
    private JComponent wrapWithTitledBorder(JComponent panel, String title) {
        panel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createTitledBorder(title),
                panel.getBorder()
        ));
        return panel;
    }

    /**
     * Add inner padding (EmptyBorder) to a panel.
     */
    private JComponent addPadding(JComponent panel) {
        panel.setBorder(BorderFactory.createEmptyBorder(6, 8, 6, 8));
        return panel;
    }

    /**
     * Recursively enable/disable all components in a container.
     */
    private static void setComponentTreeEnabled(Container container, boolean enabled) {
        for (Component c : container.getComponents()) {
            c.setEnabled(enabled);
            if (c instanceof Container cont) {
                setComponentTreeEnabled(cont, enabled);
            }
        }
    }

    /**
     * Enable or disable all configuration panels (everything except the master panel).
     */
    private void setConfigPanelsEnabled(boolean enabled) {
        for (JComponent panel : configPanels) {
            setComponentTreeEnabled(panel, enabled);
        }
    }

    /**
     * Expose the scrollable UI component for Burp's tab API.
     *
     * @return the main UI component (this panel)
     */
    public Component getUiComponent() {
        return this;
    }

    /**
     * Optional lifecycle hook: called when the tab is shown to allow panels to refresh
     * their displayed values from the central configuration.
     *
     * Implementations of the individual panels should provide a public method named
     * `loadFromConfig()` (or similar) which gets invoked here.
     */
    public void loadFromConfig() {
        // Defensive calls - panels implement their own config-loading logic
        safeInvokePanelLoad(masterSettingsPanel);
        safeInvokePanelLoad(domainSettingsPanel);
        safeInvokePanelLoad(credentialsSettingsPanel);
        safeInvokePanelLoad(delegationSettingsPanel);
        safeInvokePanelLoad(authenticationStrategySettingsPanel);
        safeInvokePanelLoad(scopeSettingsPanel);
        safeInvokePanelLoad(customSPNPanel);
        safeInvokePanelLoad(loggingSettingsPanel);
    }

    /**
     * Flush all panel state into the Config singleton.
     * Must be called before persisting configuration.
     */
    public void saveToConfig() {
        safeInvokePanelMethod(masterSettingsPanel, "saveToConfig");
        safeInvokePanelMethod(domainSettingsPanel, "saveToConfig");
        safeInvokePanelMethod(credentialsSettingsPanel, "saveToConfig");
        safeInvokePanelMethod(delegationSettingsPanel, "saveToConfig");
        safeInvokePanelMethod(authenticationStrategySettingsPanel, "saveToConfig");
        safeInvokePanelMethod(scopeSettingsPanel, "saveToConfig");
        safeInvokePanelMethod(customSPNPanel, "saveToConfig");
        safeInvokePanelMethod(loggingSettingsPanel, "saveToConfig");
    }

    // reflection-lite helper to invoke loadFromConfig() on panels that implement it.
    private void safeInvokePanelLoad(Object panel) {
        safeInvokePanelMethod(panel, "loadFromConfig");
    }

    private void safeInvokePanelMethod(Object panel, String methodName) {
        try {
            panel.getClass().getMethod(methodName).invoke(panel);
        } catch (NoSuchMethodException ignored) {
            // panel does not implement this method - that's fine
        } catch (Exception e) {
            LogUtil.logException(Config.LogLevel.VERBOSE, e);
        }
    }

}
