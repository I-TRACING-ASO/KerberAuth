package kerberauth.ui;

import javax.swing.*;
import java.awt.*;
import java.io.*;
import java.nio.file.Path;
import java.nio.file.Paths;

import kerberauth.KerberAuthExtension;
import kerberauth.config.Config;
import kerberauth.util.LogUtil;

/**
 * Panel for Kerberos delegation settings.
 *
 * Manages the krb5.conf file which controls whether tickets are forwardable
 * (required for delegation). Credential delegation itself is always requested
 * via requestDelegPolicy — the KDC decides based on the OK-AS-DELEGATE flag.
 */
public class DelegationSettingsPanel extends JPanel {

    private final JTextField krb5FileField;
    private final JButton changeKrb5FileButton;
    private final JButton createKrb5ConfButton;
    private final JButton checkConfigButton;
    private final JButton krb5FileHelpButton;
    private final JButton checkConfigHelpButton;

    private static final String KRB5_FILE_HELP =
            "The krb5.conf file controls Kerberos client behaviour.\n\n"
            + "For delegation to work, the file must contain:\n"
            + "  [libdefaults]\n"
            + "      forwardable = true\n\n"
            + "If no file is specified, the system default is used.";

    private static final String CHECK_CONFIG_HELP =
            "Check if the specified krb5.conf file sets \"forwardable = true\" in [libdefaults].";

    public DelegationSettingsPanel() {
        super(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(4, 4, 4, 4);
        gbc.anchor = GridBagConstraints.WEST;

        // Row 0: krb5.conf file label + field + help
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.fill = GridBagConstraints.NONE;
        gbc.weightx = 0.0;
        this.add(new JLabel("krb5.conf file:"), gbc);

        gbc.gridx = 1;
        gbc.gridwidth = 3;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        krb5FileField = new JTextField();
        krb5FileField.setEditable(false);
        this.add(krb5FileField, gbc);

        gbc.gridx = 4;
        gbc.gridwidth = 1;
        gbc.fill = GridBagConstraints.NONE;
        gbc.weightx = 0.0;
        krb5FileHelpButton = new JButton("?");
        this.add(krb5FileHelpButton, gbc);

        // Row 1: buttons
        gbc.gridy = 1;
        gbc.gridx = 1;
        gbc.fill = GridBagConstraints.NONE;
        changeKrb5FileButton = new JButton("Change...");
        this.add(changeKrb5FileButton, gbc);

        gbc.gridx = 2;
        createKrb5ConfButton = new JButton("Create krb5.conf file");
        this.add(createKrb5ConfButton, gbc);

        gbc.gridx = 3;
        checkConfigButton = new JButton("Check current config");
        this.add(checkConfigButton, gbc);

        gbc.gridx = 4;
        checkConfigHelpButton = new JButton("?");
        this.add(checkConfigHelpButton, gbc);

        // Row 2: info label
        gbc.gridy = 2;
        gbc.gridx = 0;
        gbc.gridwidth = 5;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        this.add(new JLabel("Credential delegation is automatically negotiated with the KDC (OK-AS-DELEGATE flag)."), gbc);

        // --- Action listeners ---
        changeKrb5FileButton.addActionListener(e -> browseKrb5File());
        createKrb5ConfButton.addActionListener(e -> createKrb5ConfFile());
        checkConfigButton.addActionListener(e -> checkDelegationConfig());
        krb5FileHelpButton.addActionListener(new HelpButtonActionListener(KRB5_FILE_HELP));
        checkConfigHelpButton.addActionListener(new HelpButtonActionListener(CHECK_CONFIG_HELP));
    }

    // --- Browse for existing krb5.conf ---
    private void browseKrb5File() {
        JFileChooser chooser = new JFileChooser();
        chooser.setSelectedFile(new File("krb5.conf"));
        chooser.setDialogTitle("Select krb5.conf file");
        int returnVal = chooser.showOpenDialog(KerberAuthExtension.suiteFrame());

        if (returnVal == JFileChooser.APPROVE_OPTION) {
            File f = chooser.getSelectedFile();

            if (!checkConfigFileForForwardable(f.getPath())) {
                int n = JOptionPane.showConfirmDialog(KerberAuthExtension.suiteFrame(),
                        "This krb5.conf file does not have \"forwardable=true\" set — "
                        + "delegation won't work.\n\nContinue anyway?",
                        "Warning", JOptionPane.YES_NO_OPTION);
                if (n == JOptionPane.NO_OPTION) {
                    return;
                }
            }

            setKrb5FilePath(f.getPath());
        }
    }

    // --- Create new krb5.conf with forwardable=true ---
    private void createKrb5ConfFile() {
        JFileChooser chooser = new JFileChooser();
        chooser.setSelectedFile(new File("krb5.conf"));
        chooser.setDialogTitle("Create new krb5.conf file");
        int returnVal = chooser.showSaveDialog(KerberAuthExtension.suiteFrame());

        if (returnVal != JFileChooser.APPROVE_OPTION) {
            return;
        }

        File f = chooser.getSelectedFile();

        if (f.exists()) {
            int n = JOptionPane.showConfirmDialog(KerberAuthExtension.suiteFrame(),
                    "File already exists — overwrite it?",
                    "File already exists", JOptionPane.YES_NO_OPTION);
            if (n == JOptionPane.NO_OPTION) {
                return;
            }
        }

        try (PrintWriter writer = new PrintWriter(f)) {
            writer.println("[libdefaults]");
            writer.println("\tforwardable = true");
        } catch (FileNotFoundException ex) {
            JOptionPane.showMessageDialog(KerberAuthExtension.suiteFrame(),
                    "Could not write to file: " + f.getPath(),
                    "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        int n = JOptionPane.showConfirmDialog(KerberAuthExtension.suiteFrame(),
                "File created successfully — use this as the krb5.conf file?",
                "Success", JOptionPane.YES_NO_OPTION);
        if (n == JOptionPane.YES_OPTION) {
            setKrb5FilePath(f.getPath());
        }
    }

    // --- Check if current krb5.conf has forwardable=true ---
    private void checkDelegationConfig() {
        Config config = Config.getInstance();
        Path path = config.getKrb5ConfPath();

        if (path == null || path.toString().isEmpty()) {
            JOptionPane.showMessageDialog(KerberAuthExtension.suiteFrame(),
                    "No krb5.conf file has been specified.\n\n"
                    + "Use \"Change...\" to specify a file, or \"Create krb5.conf file\" to create one.",
                    "No config file", JOptionPane.WARNING_MESSAGE);
            return;
        }

        File f = path.toFile();
        if (!f.exists()) {
            JOptionPane.showMessageDialog(KerberAuthExtension.suiteFrame(),
                    "Can't find krb5.conf file: " + path
                    + "\n\nDelegation won't work.",
                    "File not found", JOptionPane.ERROR_MESSAGE);
            return;
        }

        if (checkConfigFileForForwardable(path.toString())) {
            JOptionPane.showMessageDialog(KerberAuthExtension.suiteFrame(),
                    "krb5.conf found at " + path
                    + "\n\"forwardable = true\" is set — delegation should work.",
                    "Success", JOptionPane.INFORMATION_MESSAGE);
        } else {
            JOptionPane.showMessageDialog(KerberAuthExtension.suiteFrame(),
                    "krb5.conf found at " + path
                    + "\nbut \"forwardable = true\" is NOT set — delegation won't work.\n\n"
                    + "Try editing the file, or creating a new one.",
                    "Warning", JOptionPane.WARNING_MESSAGE);
        }
    }

    // --- Parse krb5.conf for [libdefaults] forwardable=true ---
    private static boolean checkConfigFileForForwardable(String configFilename) {
        try (BufferedReader br = new BufferedReader(new FileReader(configFilename))) {
            boolean inLibDefaults = false;
            String line;
            while ((line = br.readLine()) != null) {
                String trimmed = line.trim();
                if (trimmed.equals("[libdefaults]")) {
                    inLibDefaults = true;
                } else if (trimmed.startsWith("[")) {
                    inLibDefaults = false;
                }
                if (inLibDefaults && trimmed.replace(" ", "").replace("\t", "")
                        .equals("forwardable=true")) {
                    return true;
                }
            }
        } catch (IOException e) {
            LogUtil.log(Config.LogLevel.NORMAL,
                    "Couldn't read config file " + configFilename + ": " + e.getMessage());
        }
        return false;
    }

    /**
     * Check if the TGT forwardable flag is set on a Subject's Kerberos ticket.
     * Called after login to inform the user about delegation capability.
     */
    public static boolean checkTgtForwardableFlag(javax.security.auth.Subject subject) {
        for (Object ob : subject.getPrivateCredentials()) {
            if (ob instanceof javax.security.auth.kerberos.KerberosTicket kt) {
                boolean[] flags = kt.getFlags();
                return flags[1]; // forwardable flag
            }
        }
        return false;
    }

    // --- Set the krb5.conf path in Config and update the UI field ---
    private void setKrb5FilePath(String path) {
        krb5FileField.setText(path);
        Config config = Config.getInstance();
        config.setKrb5ConfPath(Paths.get(path));
        config.setKrb5Config();
    }

    public void loadFromConfig() {
        Path path = Config.getInstance().getKrb5ConfPath();
        krb5FileField.setText(path != null ? path.toString() : "");
    }

    public void saveToConfig() {
        String text = krb5FileField.getText().trim();
        if (!text.isEmpty()) {
            Config.getInstance().setKrb5ConfPath(Paths.get(text));
        } else {
            Config.getInstance().setKrb5ConfPath(null);
        }
    }
}
