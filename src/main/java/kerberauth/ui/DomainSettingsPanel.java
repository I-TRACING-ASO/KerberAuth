package kerberauth.ui;

import kerberauth.KerberAuthExtension;
import kerberauth.config.Config;
import kerberauth.kerberos.KerberosManager;
import kerberauth.util.DomainUtil;
import kerberauth.util.LogUtil;

import javax.naming.Context;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.List;

/**
 * Panel for Kerberos domain/KDC settings.
 * This includes fields for KDC hostname and Kerberos Realm (domain).
 */
public class DomainSettingsPanel extends JPanel {

    private Config config = Config.getInstance();

    private final String domainDnsNameHelpString = "DNS name of the domain to authenticate against - not the NETBIOS name.";
    private final String kdcHelpString = "Hostname of a KDC (domain controller) for this domain.";
    private final String kdcTestSuccessString = "Successfully contacted Kerberos service.";
    private final String domainControlsHelpString = "\"Change...\" lets you change the Domain DNS Name and KDC Host.\n\n" +
                "\"Autolocate KDC\" will do a DNS SRV lookup to try to find a KDC for the given domain.\n\n" +
                "\"Test domain settings\" will check that the Kerberos service can be contacted successfully.";

    private final JLabel domainDnsLabel = new JLabel("Domain DNS Name");
    private final JLabel kdcLabel = new JLabel("KDC Host");
    private final JButton changeButton = new JButton("Change...");
    private final JButton autolocateButton = new JButton("Autolocate KDC");
    private final JButton testButton = new JButton("Test Domain Settings");
    private final JButton domainDnsNameHelpButton = new JButton("?");
    private final JButton kdcHelpButton = new JButton("?");
    private final JButton domainControlsHelpButton = new JButton("?");

    private JTextField domainDnsField = new JTextField();
    private JTextField kdcField = new JTextField();
    private JTextField domainStatusField = new JTextField();

    public DomainSettingsPanel() {
        super(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);

        domainDnsField.setEditable(false);
        kdcField.setEditable(false);
        domainStatusField.setEditable(false);

        // Domain field
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 0.0;
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.gridwidth = 1;
        this.add(domainDnsLabel, gbc);

        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        gbc.gridx = 1;
        gbc.gridy = 0;
        gbc.gridwidth = 5;
        this.add(domainDnsField, gbc);

        gbc.fill = GridBagConstraints.NONE;
        gbc.weightx = 0.0;
        gbc.gridx = 6;
        gbc.gridy = 0;
        gbc.gridwidth = 1;
        this.add(domainDnsNameHelpButton, gbc);

        // KDC Host field
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 0.0;
        gbc.gridx = 0;
        gbc.gridy = 1;
        gbc.gridwidth = 1;
        this.add(kdcLabel, gbc);

        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        gbc.gridx = 1;
        gbc.gridy = 1;
        gbc.gridwidth = 5;
        this.add(kdcField, gbc);

        gbc.fill = GridBagConstraints.NONE;
        gbc.weightx = 0.0;
        gbc.gridx = 6;
        gbc.gridy = 1;
        gbc.gridwidth = 1;
        this.add(kdcHelpButton, gbc);

        // Buttons row
        gbc.gridwidth = 1;
        gbc.fill = GridBagConstraints.NONE;
        gbc.weightx = 0.0;
        gbc.gridx = 1;
        gbc.gridy = 2;
        this.add(changeButton, gbc);

        gbc.gridx = 2;
        this.add(autolocateButton, gbc);

        gbc.gridx = 3;
        this.add(testButton, gbc);

        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        gbc.gridx = 4;
        gbc.gridy = 2;
        gbc.gridwidth = 2;
        this.add(domainStatusField, gbc);

        gbc.fill = GridBagConstraints.NONE;
        gbc.weightx = 0.0;
        gbc.gridx = 6;
        gbc.gridy = 2;
        gbc.gridwidth = 1;
        this.add(domainControlsHelpButton, gbc);

        // Button actions
        changeButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                changeDomainSettings();
            }
        });

        autolocateButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                kdcAuto();
            }
        });

        testButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                pingKDC();
            }
        });

        // Help button actions: show help dialogs
        domainDnsNameHelpButton.addActionListener(new HelpButtonActionListener(domainDnsNameHelpString));
        kdcHelpButton.addActionListener(new HelpButtonActionListener(kdcHelpString));
        domainControlsHelpButton.addActionListener(new HelpButtonActionListener(domainControlsHelpString));
    }

    private void changeDomainSettings() {
        String domainDnsName = config.getDomain() != null ? config.getDomain() : "";
        String kdcHost = config.getKdc() != null ? config.getKdc() : "";

        JTextField newDomainDnsField = new JTextField();
        newDomainDnsField.setText(domainDnsName);
        JTextField newKdcField = new JTextField();
        newKdcField.setText(kdcHost);
        final JComponent[] inputs = new JComponent[] {
                new JLabel("Domain DNS Name"), newDomainDnsField,
                new JLabel("KDC Host"), newKdcField};
        JOptionPane.showMessageDialog(KerberAuthExtension.suiteFrame(), inputs, "Change domain settings", JOptionPane.PLAIN_MESSAGE);

        if (newDomainDnsField.getText().endsWith(".")) {
            JOptionPane.showMessageDialog(KerberAuthExtension.suiteFrame(),
                "Removing dot from end of DNS domain name", 
                "Info", JOptionPane.INFORMATION_MESSAGE);
            newDomainDnsField.setText(newDomainDnsField
                    .getText().substring(0, newDomainDnsField.getText().length() - 1));
        }
        
        if (newKdcField.getText().endsWith(".")) {
            JOptionPane.showMessageDialog(KerberAuthExtension.suiteFrame(),
                "Removing dot from end of KDC hostname", 
                "Info", JOptionPane.INFORMATION_MESSAGE);
            newKdcField.setText(newKdcField
                    .getText().substring(0, newKdcField.getText().length() - 1));
        }

        if (!DomainUtil.checkHostnameRegexp(newDomainDnsField.getText())) {
            JOptionPane.showMessageDialog(KerberAuthExtension.suiteFrame(),
                "DNS domain name does not match hostname regexp - please check",
                "Warning", JOptionPane.WARNING_MESSAGE);
        } else if (!DomainUtil.isMultiComponentHostname(newDomainDnsField.getText())) {
            JOptionPane.showMessageDialog(KerberAuthExtension.suiteFrame(),
                "This seems to be a single-component DNS name - this isn't valid for Windows domains but might be valid for other Kerberos realms",
                "Warning", JOptionPane.WARNING_MESSAGE);
        }

        if (!DomainUtil.checkHostnameRegexp(newKdcField.getText())) {
            if (!newKdcField.getText().isEmpty()) {
                JOptionPane.showMessageDialog(KerberAuthExtension.suiteFrame(),
                    "KDC hostname does not match hostname regexp - please check",
                    "Warning", JOptionPane.WARNING_MESSAGE);
            } else {
                JOptionPane.showMessageDialog(KerberAuthExtension.suiteFrame(),
                    "You will need to also set the KDC Host before authentication will work.\n\nMaybe try the Auto button.",
                    "Warning", JOptionPane.WARNING_MESSAGE);
            }
        }

        if (!newDomainDnsField.getText().equals(domainDnsName)
                || !newKdcField.getText().equals(kdcHost)) // don't do anything if values are unchanged
        {
            domainDnsName = newDomainDnsField.getText();
            domainDnsField.setText(newDomainDnsField.getText());
            kdcHost = newKdcField.getText();
            kdcField.setText(newKdcField.getText());
            domainStatusField.setText("");

            if (domainDnsName.isEmpty()) {
                domainStatusField.setText("Domain DNS name cannot be empty");
            } else if (kdcHost.isEmpty()) {
                domainStatusField.setText("KDC host cannot be empty");
            }

            config.setDomainAndKdc(domainDnsName, kdcHost);
        }

        domainDnsField.setText(newDomainDnsField.getText());
        kdcField.setText(newKdcField.getText());
    }

    private void kdcAuto() {
        String domainDnsName = config.getDomain() != null ? config.getDomain() : "";
        String kdcHost = config.getKdc() != null ? config.getKdc() : "";

        if (domainDnsName.isEmpty()) {
            JOptionPane.showMessageDialog(KerberAuthExtension.suiteFrame(),
                    "Have to set the domain DNS name first", "Failure",
                    JOptionPane.ERROR_MESSAGE);
            return;
        }

        List<String> results = new ArrayList<String>();
        try {
            Hashtable<String, String> envProps = new Hashtable<String, String>();
            envProps.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.dns.DnsContextFactory");
            DirContext dnsContext = new InitialDirContext(envProps);
            Attributes dnsEntries = dnsContext.getAttributes("_kerberos._tcp."
                    + domainDnsName.toLowerCase(), new String[] { "SRV" });
            if (dnsEntries != null) {
                Attribute attr = dnsEntries.get("SRV");

                if (attr != null) {
                    for (int i = 0; i < attr.size(); i++) {
                        String s = (String) attr.get(i);
                        String[] parts = s.split(" ");
                        String namePart = parts[parts.length - 1];
                        if (namePart.endsWith(".")) {
                            namePart = namePart.substring(0,
                                    namePart.length() - 1);
                        }
                        results.add(namePart);
                    }
                }
            }
        } catch (Exception e) {
            if (e.getMessage().startsWith("DNS name not found")) {
                JOptionPane.showMessageDialog(KerberAuthExtension.suiteFrame(),
                    "Couldn't find any suitable DNS SRV records - is (one of) your DNS server(s) in the domain?",
                    "Failure", JOptionPane.ERROR_MESSAGE);
            } else {
                JOptionPane.showMessageDialog(KerberAuthExtension.suiteFrame(),
                    "Failure doing DNS SRV lookup", 
                    "Failure", JOptionPane.ERROR_MESSAGE);
                LogUtil.log(Config.LogLevel.NORMAL, "Unexpected error when doing DNS SRV lookup: " + e.getMessage());
                LogUtil.logException(Config.LogLevel.VERBOSE, e);
            }
            return;
        }

        if (results.size() == 0) {
            JOptionPane.showMessageDialog(KerberAuthExtension.suiteFrame(), 
                "No DNS entries for KDC found",
                "Failure", JOptionPane.ERROR_MESSAGE);
            return;
        }

        String selectedValue = "";

        if (results.size() == 1) {
            selectedValue = results.get(0);
        } else {
            Object[] possibilities = new Object[results.size()];
            for (int ii = 0; ii < results.size(); ii++) {
                possibilities[ii] = results.get(ii);
            }
            selectedValue = (String) JOptionPane.showInputDialog(KerberAuthExtension.suiteFrame(),
                    "Multiple KDCs were found", "Select KDC",
                    JOptionPane.PLAIN_MESSAGE, null, possibilities,
                    results.get(0));
        }

        if (!selectedValue.isEmpty()) {
            kdcHost = selectedValue;
            kdcField.setText(selectedValue);
            domainStatusField.setText("");

            config.setDomainAndKdc(domainDnsName, kdcHost);
        }
    }

    private void pingKDC() {
        String domainDns = config.getDomain() != null ? config.getDomain() : "";
        String kdcHost = config.getKdc() != null ? config.getKdc() : "";

        if (domainDns.isEmpty()) {
            JOptionPane.showMessageDialog(KerberAuthExtension.suiteFrame(), 
                "Domain DNS name not set yet",
                "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        if (kdcHost.isEmpty()) {
            JOptionPane.showMessageDialog(KerberAuthExtension.suiteFrame(), 
                "KDC hostname not set yet",
                "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        try {
            Socket client = new Socket();
            client.connect(new InetSocketAddress(kdcHost, 88), 2000);
            client.close();
        } catch (UnknownHostException e) {
            domainStatusField.setText("KDC hostname couldn't be resolved");
            JOptionPane.showMessageDialog(KerberAuthExtension.suiteFrame(),
                "Couldn't resolve KDC hostname:" + kdcHost, 
                "Failure", JOptionPane.ERROR_MESSAGE);
            return;
        } catch (SocketTimeoutException e) {
            domainStatusField.setText("Couldn't connect to port 88 (Kerberos) on KDC - socket timed out");
            JOptionPane.showMessageDialog(KerberAuthExtension.suiteFrame(),
                "Couldn't connect to port 88 (Kerberos) on KDC:" + kdcHost+ ". Socket timed out - check hostname?",
                "Failure", JOptionPane.ERROR_MESSAGE);
            return;
        } catch (Exception e) {
            domainStatusField.setText("Failed to connect to port 88 on KDC");
            JOptionPane.showMessageDialog(KerberAuthExtension.suiteFrame(),
                "Failed to connect to port 88 on " + kdcHost + ": " + e.getMessage(), 
                "Failure", JOptionPane.ERROR_MESSAGE);
            LogUtil.log(Config.LogLevel.NORMAL, "Unexpected error when testing connectivity to KDC: " + e.getMessage());
            LogUtil.logException(Config.LogLevel.VERBOSE, e);
            return;
        }

        config.setKrb5Config();

        try {
            KerberosManager.getInstance().loginTestUser();
        } catch (Exception e) {
            if (e.getMessage().startsWith("Client not found in Kerberos database")) {
                domainStatusField.setText(kdcTestSuccessString);
                JOptionPane.showMessageDialog(KerberAuthExtension.suiteFrame(), 
                    kdcTestSuccessString,
                    "Success", JOptionPane.INFORMATION_MESSAGE);
            } else if (e.getMessage().contains("(68)")) {
                domainStatusField.setText("Failed to contact Kerberos service - error code 68 suggests that KDC is valid but domain DNS name is wrong");
                JOptionPane.showMessageDialog(KerberAuthExtension.suiteFrame(),
                    "Failed to contact Kerberos service - error code 68 suggests that KDC is valid but domain DNS name is wrong",
                    "Failure", JOptionPane.ERROR_MESSAGE);
            } else {
                domainStatusField.setText("Connected to port 88, but failed to contact Kerberos service: " + e.getMessage());
                JOptionPane.showMessageDialog(KerberAuthExtension.suiteFrame(),
                    "Connected to port 88, but failed to contact Kerberos service: " + e.getMessage(), "Failure", JOptionPane.ERROR_MESSAGE);
                LogUtil.log(Config.LogLevel.NORMAL, "Unexpected error when making test Kerberos request to KDC: " + e.getMessage());
                LogUtil.logException(Config.LogLevel.VERBOSE, e);
            }
        }
    }

    /**
     * Load values from Config singleton into the UI fields.
     */
    public void loadFromConfig() {
        kdcField.setText(config.getKdc() != null ? config.getKdc() : "");
        domainDnsField.setText(config.getDomain() != null ? config.getDomain() : "");
    }

    /**
     * Save values from UI fields into Config singleton.
     */
    public void saveToConfig() {
        config.setKdc(kdcField.getText().trim());
        config.setDomain(domainDnsField.getText().trim());
    }
}
