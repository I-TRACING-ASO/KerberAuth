package kerberauth.ui;

import kerberauth.KerberAuthExtension;
import kerberauth.config.Config;
import kerberauth.util.DomainUtil;

import javax.swing.*;
import java.awt.*;

/**
 * Panel for configuring the scope of Kerberos authentication.
 *
 * Mirrors the Berserko scope panel with:
 * - Checkboxes: everything in scope, whole domain, plain hostnames, ignore NTLM
 * - A hosts-in-scope list with Add/Edit/Remove buttons
 * - A help button
 */
public class ScopeSettingsPanel extends JPanel {

    private final JCheckBox everythingInScopeCheck;
    private final JCheckBox wholeDomainInScopeCheck;
    private final JCheckBox includePlainhostnamesCheck;
    private final JCheckBox ignoreNTLMServersCheck;
    private boolean loading = false;
    private final DefaultListModel<String> scopeListModel;
    private final JList<String> scopeListBox;
    private final JButton scopeAddButton;
    private final JButton scopeEditButton;
    private final JButton scopeRemoveButton;
    private final JButton scopeHelpButton;

    private static final String SCOPE_HELP =
            "In this section, you can define which hosts are in scope for Kerberos authentication.\n\n"
            + "\"All hosts in this Kerberos domain in scope\" is the default. "
            + "This means the extension will attempt Kerberos authentication only to web servers "
            + "whose hostname ends with the domain DNS name.\n\n"
            + "\"All hosts in scope for Kerberos authentication\" means you don't need to specify "
            + "the scope manually. The potential disadvantage is that it might lead to requests "
            + "to the KDC for hosts not in the domain.\n\n"
            + "The list allows you to specify additional hosts in scope. "
            + "It is ignored when \"All hosts in scope\" is selected.\n\n"
            + "\"Plain hostnames considered part of domain\" enables authentication against "
            + "hosts specified by unqualified hostnames (no domain suffix).\n\n"
            + "\"Do not perform Kerberos authentication to servers which support NTLM\" skips "
            + "Kerberos for hosts that also advertise NTLM.";

    public ScopeSettingsPanel() {
        super(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);

        // Left column: checkboxes (rows 0-3)
        everythingInScopeCheck = new JCheckBox("All hosts in scope for Kerberos authentication");
        wholeDomainInScopeCheck = new JCheckBox("All hosts in this Kerberos domain in scope");
        includePlainhostnamesCheck = new JCheckBox("Plain hostnames considered part of domain");
        ignoreNTLMServersCheck = new JCheckBox("Do not authenticate to servers which support NTLM");

        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 0.0;
        this.add(everythingInScopeCheck, gbc);

        gbc.gridy = 1;
        this.add(wholeDomainInScopeCheck, gbc);

        gbc.gridy = 2;
        this.add(includePlainhostnamesCheck, gbc);

        gbc.gridy = 3;
        this.add(ignoreNTLMServersCheck, gbc);

        // Right column: "Hosts in scope:" label (row 0)
        gbc.gridx = 1;
        gbc.gridy = 0;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        this.add(new JLabel("Hosts in scope:"), gbc);

        // Right column: scope list (rows 1-3, spanning 3 rows)
        scopeListModel = new DefaultListModel<>();
        scopeListBox = new JList<>(scopeListModel);
        scopeListBox.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        JScrollPane scopePane = new JScrollPane(scopeListBox);

        gbc.gridx = 1;
        gbc.gridy = 1;
        gbc.gridheight = 3;
        gbc.fill = GridBagConstraints.BOTH;
        gbc.weightx = 2.0;
        gbc.weighty = 1.0;
        this.add(scopePane, gbc);
        gbc.gridheight = 1;
        gbc.weighty = 0.0;

        // Far-right column: Add/Edit/Remove buttons (rows 1-3) + Help (row 0)
        gbc.gridx = 2;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 0.0;

        scopeAddButton = new JButton("Add");
        scopeEditButton = new JButton("Edit");
        scopeRemoveButton = new JButton("Remove");
        scopeHelpButton = new JButton("?");

        gbc.gridy = 1;
        this.add(scopeAddButton, gbc);
        gbc.gridy = 2;
        this.add(scopeEditButton, gbc);
        gbc.gridy = 3;
        this.add(scopeRemoveButton, gbc);

        gbc.gridx = 2;
        gbc.gridy = 0;
        gbc.fill = GridBagConstraints.NONE;
        this.add(scopeHelpButton, gbc);

        // --- Action listeners ---
        scopeAddButton.addActionListener(e -> addHost());
        scopeEditButton.addActionListener(e -> editHost());
        scopeRemoveButton.addActionListener(e -> removeHost());
        scopeHelpButton.addActionListener(new HelpButtonActionListener(SCOPE_HELP));

        // Sync checkboxes to Config on change
        everythingInScopeCheck.addActionListener(e -> { if (!loading) saveToConfig(); });
        wholeDomainInScopeCheck.addActionListener(e -> { if (!loading) saveToConfig(); });
        includePlainhostnamesCheck.addActionListener(e -> { if (!loading) saveToConfig(); });
        ignoreNTLMServersCheck.addActionListener(e -> { if (!loading) saveToConfig(); });
    }

    private String hostDialogBox(String initial) {
        String result = JOptionPane.showInputDialog(KerberAuthExtension.suiteFrame(), "Hostname or pattern (* = any, ? = any except dot):", initial);
        return result == null ? "" : result.trim();
    }

    private void addHost() {
        String s = hostDialogBox("");
        while (!s.isEmpty() && !DomainUtil.checkHostnameRegexp(s) && !s.contains("*") && !s.contains("?")) {
            JOptionPane.showMessageDialog(KerberAuthExtension.suiteFrame(), "Not a valid hostname expression", "Error", JOptionPane.ERROR_MESSAGE);
            s = hostDialogBox(s);
        }
        if (!s.isEmpty()) {
            for (int i = 0; i < scopeListModel.getSize(); i++) {
                if (s.equals(scopeListModel.getElementAt(i))) {
                    JOptionPane.showMessageDialog(KerberAuthExtension.suiteFrame(), "Already present in list", "Error", JOptionPane.ERROR_MESSAGE);
                    return;
                }
            }
            scopeListModel.addElement(s);
            saveToConfig();
        }
    }

    private void editHost() {
        int index = scopeListBox.getSelectedIndex();
        if (index == -1) return;
        String s = hostDialogBox(scopeListModel.getElementAt(index));
        while (!s.isEmpty() && !DomainUtil.checkHostnameRegexp(s) && !s.contains("*") && !s.contains("?")) {
            JOptionPane.showMessageDialog(KerberAuthExtension.suiteFrame(), "Not a valid hostname expression", "Error", JOptionPane.ERROR_MESSAGE);
            s = hostDialogBox(s);
        }
        if (!s.isEmpty()) {
            for (int i = 0; i < scopeListModel.getSize(); i++) {
                if (i != index && s.equals(scopeListModel.getElementAt(i))) {
                    JOptionPane.showMessageDialog(KerberAuthExtension.suiteFrame(), "Already present in list", "Error", JOptionPane.ERROR_MESSAGE);
                    return;
                }
            }
            scopeListModel.setElementAt(s, index);
            saveToConfig();
        }
    }

    private void removeHost() {
        int index = scopeListBox.getSelectedIndex();
        if (index != -1) {
            scopeListModel.removeElementAt(index);
            saveToConfig();
        }
    }

    public void loadFromConfig() {
        loading = true;
        try {
            Config config = Config.getInstance();
            everythingInScopeCheck.setSelected(config.isEverythingInScope());
            wholeDomainInScopeCheck.setSelected(config.isWholeDomainInScope());
            includePlainhostnamesCheck.setSelected(config.isPlainhostExpand());
            ignoreNTLMServersCheck.setSelected(config.isIgnoreNTLMServers());

            scopeListModel.clear();
            for (String host : config.getHostsInScope()) {
                scopeListModel.addElement(host);
            }
        } finally {
            loading = false;
        }
    }

    public void saveToConfig() {
        Config config = Config.getInstance();
        config.setEverythingInScope(everythingInScopeCheck.isSelected());
        config.setWholeDomainInScope(wholeDomainInScopeCheck.isSelected());
        config.setPlainhostExpand(includePlainhostnamesCheck.isSelected());
        config.setIgnoreNTLMServers(ignoreNTLMServersCheck.isSelected());

        config.clearHostsInScope();
        for (int i = 0; i < scopeListModel.getSize(); i++) {
            config.addHostInScope(scopeListModel.getElementAt(i));
        }

        warnIfProactiveAndEverythingInScope();
    }

    private void warnIfProactiveAndEverythingInScope() {
        Config config = Config.getInstance();
        if (config.isEverythingInScope()
                && config.getAuthenticationStrategy() == Config.AuthenticationStrategy.PROACTIVE) {
            JOptionPane.showMessageDialog(KerberAuthExtension.suiteFrame(),
                "Combining 'All hosts in scope' with 'Proactive' strategy is not recommended.\n"
                + "This will cause Kerberos authentication attempts to every host passing through Burp,\n"
                + "which may cause performance issues and leak information to the KDC.",
                "Warning", JOptionPane.WARNING_MESSAGE);
        }
    }
}
