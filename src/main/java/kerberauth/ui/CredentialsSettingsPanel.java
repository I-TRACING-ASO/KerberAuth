package kerberauth.ui;

import kerberauth.KerberAuthExtension;
import kerberauth.authenticator.KerberosCallbackHandler;
import kerberauth.config.Config;
import kerberauth.kerberos.KerberosManager;
import kerberauth.manager.UserManager;
import kerberauth.model.UserEntry;
import kerberauth.util.LogUtil;
import kerberauth.util.UIUtil;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

/**
 * Panel for managing Kerberos user credentials.
 * 
 * - Displays a table of configured users (principal, header selector, enabled).
 * - Allows adding and removing users.
 * - Passwords are stored transiently in memory only.
 */
public class CredentialsSettingsPanel extends JPanel {

    private final JTable userTable;
    private final UserTableModel tableModel;
    private final JButton addButton;
    private final JButton removeButton;
    private final JButton testButton;
    private final JButton changePasswordButton;
    private final JCheckBox savePasswordsCheck;
    private final JTextField customHeaderField;
    private boolean loading = false;

    public CredentialsSettingsPanel() {
        super(new BorderLayout(5, 5));
        setBorder(BorderFactory.createEmptyBorder(6, 8, 6, 8));

        tableModel = new UserTableModel();
        userTable = new JTable(tableModel);
        userTable.setFillsViewportHeight(true);

        // Limit table to 6 visible rows
        userTable.setPreferredScrollableViewportSize(new Dimension(
                userTable.getPreferredScrollableViewportSize().width,
                userTable.getRowHeight() * 6));

        JScrollPane scrollPane = new JScrollPane(userTable);
        UIUtil.installWheelPassthrough(scrollPane);

        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        addButton = new JButton("Add User");
        removeButton = new JButton("Remove Selected");
        testButton = new JButton("Test Credentials");
        changePasswordButton = new JButton("Change Password");
        savePasswordsCheck = new JCheckBox("Save passwords in project");
        buttonPanel.add(addButton);
        buttonPanel.add(removeButton);
        buttonPanel.add(testButton);
        buttonPanel.add(changePasswordButton);
        buttonPanel.add(savePasswordsCheck);

        customHeaderField = new JTextField(15);

        JPanel headerRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        headerRow.add(new JLabel("Header name:"));
        headerRow.add(customHeaderField);

        JPanel bottomPanel = new JPanel(new BorderLayout());
        bottomPanel.add(buttonPanel, BorderLayout.NORTH);
        bottomPanel.add(headerRow, BorderLayout.SOUTH);

        this.add(scrollPane, BorderLayout.CENTER);
        this.add(bottomPanel, BorderLayout.SOUTH);

        addButton.addActionListener(e -> addUser());
        removeButton.addActionListener(e -> removeSelectedUser());
        testButton.addActionListener(e -> testSelectedUser());
        changePasswordButton.addActionListener(e -> changeSelectedUserPassword());

        savePasswordsCheck.addActionListener(e -> {
            if (!loading) Config.getInstance().setSavePasswords(savePasswordsCheck.isSelected());
        });
        customHeaderField.addActionListener(e -> {
            if (!loading) Config.getInstance().setCustomHeader(customHeaderField.getText().trim());
        });
        customHeaderField.addFocusListener(new java.awt.event.FocusAdapter() {
            @Override
            public void focusLost(java.awt.event.FocusEvent e) {
                if (!loading) Config.getInstance().setCustomHeader(customHeaderField.getText().trim());
            }
        });
    }

    private void addUser() {
        JTextField newUsernameTextField = new JTextField("");
        JPasswordField newPasswordField = new JPasswordField("");
        JTextField headerSelectorField = new JTextField("");

        java.util.List<JComponent> inputsList = new ArrayList<>();
        inputsList.add(new JLabel("Username "));
        inputsList.add(newUsernameTextField);
        inputsList.add(new JLabel("Password "));
        inputsList.add(newPasswordField);
        inputsList.add(new JLabel("Header Selector (optional) "));
        inputsList.add(headerSelectorField);

        JComponent[] inputs = inputsList.toArray(new JComponent[0]);

        while (true) {
            int result = JOptionPane.showConfirmDialog(
                KerberAuthExtension.suiteFrame(),
                inputs,
                "Add User",
                JOptionPane.OK_CANCEL_OPTION,
                JOptionPane.PLAIN_MESSAGE);

            if (result != JOptionPane.OK_OPTION) {
                return;
            }

            String username = newUsernameTextField.getText().trim();
            if (username.isEmpty()) {
                JOptionPane.showMessageDialog(
                    KerberAuthExtension.suiteFrame(),
                    "Username cannot be empty.",
                    "Input Error",
                    JOptionPane.ERROR_MESSAGE);
                continue;
            }

            if (username.contains("\\") || username.contains("/") || username.contains("@")) {
                JOptionPane.showMessageDialog(
                    KerberAuthExtension.suiteFrame(),
                    "Username shouldn't contain slash, backslash or '@' - just a plain username is required",
                    "Warning",
                    JOptionPane.WARNING_MESSAGE);
                continue;
            }

            String password = new String(newPasswordField.getPassword());
            String headerSelector = headerSelectorField.getText().trim();

            if (!headerSelector.isEmpty()) {
                boolean duplicateHeader = false;
                for (UserEntry existing : tableModel.getUsers()) {
                    if (headerSelector.equals(existing.getHeaderSelectorValue())) {
                        JOptionPane.showMessageDialog(
                            KerberAuthExtension.suiteFrame(),
                            "Header selector '" + headerSelector + "' is already used by user '" + existing.getUsername() + "'.",
                            "Duplicate Header Selector",
                            JOptionPane.ERROR_MESSAGE);
                        duplicateHeader = true;
                        break;
                    }
                }
                if (duplicateHeader) {
                    continue;
                }
            }

            UserEntry newUser = new UserEntry(username, password, headerSelector);
            tableModel.addUser(newUser);
            syncToUserManager();
            return;
        }
    }

    private void removeSelectedUser() {
        int row = userTable.getSelectedRow();
        if (row >= 0) {
            tableModel.removeUser(row);
            syncToUserManager();
        }
    }

    private void testSelectedUser() {
        int row = userTable.getSelectedRow();
        if (row < 0) {
            JOptionPane.showMessageDialog(KerberAuthExtension.suiteFrame(), "Select a user first.", "No selection", JOptionPane.WARNING_MESSAGE);
            return;
        }
        UserEntry ue = tableModel.getUsers().get(row);
        try {
            KerberosManager.getInstance().authenticateUserEntry(ue, new KerberosCallbackHandler(ue));
            JOptionPane.showMessageDialog(KerberAuthExtension.suiteFrame(),
                    "Credentials OK for " + ue.getPrincipal(),
                    "Success", JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(KerberAuthExtension.suiteFrame(),
                    "Authentication failed for " + ue.getPrincipal() + ":\n" + ex.getMessage(),
                    "Failure", JOptionPane.ERROR_MESSAGE);
            ue.setEnabled(false);
            tableModel.fireTableRowsUpdated(row, row);
            LogUtil.logException(Config.LogLevel.VERBOSE, ex);
        }
    }

    private void changeSelectedUserPassword() {
        int row = userTable.getSelectedRow();
        if (row < 0) {
            JOptionPane.showMessageDialog(KerberAuthExtension.suiteFrame(), "Select a user first.", "No selection", JOptionPane.WARNING_MESSAGE);
            return;
        }
        UserEntry ue = tableModel.getUsers().get(row);
        JPasswordField pf = new JPasswordField();
        int result = JOptionPane.showConfirmDialog(KerberAuthExtension.suiteFrame(),
                new Object[]{new JLabel("New password for " + ue.getUsername() + ":"), pf},
                "Change Password", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
        if (result == JOptionPane.OK_OPTION) {
            ue.setPassword(new String(pf.getPassword()));
            ue.invalidateLogin();
            if (ue.hasPassword() && !ue.isEnabled()) {
                ue.setEnabled(true);
            }
            LogUtil.log(Config.LogLevel.NORMAL, "Password changed for " + ue.getUsername());
            tableModel.fireTableRowsUpdated(row, row);
            syncToUserManager();
        }
    }

    public void loadFromConfig() {
        loading = true;
        try {
        Config config = Config.getInstance();
        List<UserEntry> userEntriesList = new ArrayList<>();
        
        for (String[] userArray : config.getUsers()) {
            if (userArray.length >= 2) {
                String username = userArray[0];
                String password = userArray[1];
                String header = (userArray.length >= 3) ? userArray[2] : null;
                boolean enabled = (userArray.length >= 4) ? Boolean.parseBoolean(userArray[3]) : true;
                
                UserEntry ue = new UserEntry(username, password, header);
                ue.setEnabled(enabled && ue.hasPassword());
                userEntriesList.add(ue);
            }
        }
        
        tableModel.setUsers(userEntriesList);

        // Set default user index from config
        String defUser = config.getDefaultUsername();
        if (defUser != null) {
            for (int i = 0; i < userEntriesList.size(); i++) {
                if (defUser.equals(userEntriesList.get(i).getUsername())) {
                    tableModel.setDefaultUserIndex(i);
                    break;
                }
            }
        } else if (!userEntriesList.isEmpty()) {
            tableModel.setDefaultUserIndex(0);
        }

        customHeaderField.setText(config.getCustomHeader() != null ? config.getCustomHeader() : "");
        savePasswordsCheck.setSelected(config.isSavePasswords());
        } finally {
            loading = false;
        }
    }

    public void saveToConfig() {
        Config config = Config.getInstance();
        
        config.clearUsers();
        
        for (UserEntry ue : tableModel.getUsers()) {
            String[] userArray = new String[4];
            userArray[0] = ue.getUsername();
            userArray[1] = new String(ue.getPassword());
            userArray[2] = ue.getHeaderSelectorValue() != null ? ue.getHeaderSelectorValue() : "";
            userArray[3] = String.valueOf(ue.isEnabled());
            config.addUser(userArray);
        }

        // Save default username
        int defIdx = tableModel.getDefaultUserIndex();
        List<UserEntry> allUsers = tableModel.getUsers();
        if (defIdx >= 0 && defIdx < allUsers.size()) {
            config.setDefaultUsername(allUsers.get(defIdx).getUsername());
        } else {
            config.setDefaultUsername(null);
        }

        config.setCustomHeader(customHeaderField.getText().trim());
        config.setSavePasswords(savePasswordsCheck.isSelected());
    }

    /**
     * Flush current UI state to Config and re-initialize UserManager
     * so that changes take effect immediately for Kerberos authentication.
     */
    private void syncToUserManager() {
        saveToConfig();
        UserManager.getInstance().syncFromConfig();
    }

    // ----------------------
    // Table Model
    // ----------------------

    private class UserTableModel extends AbstractTableModel {

        private final String[] columns = {"Default", "Principal", "Password", "Header Selector", "Enabled"};
        private final List<UserEntry> users = new ArrayList<>();
        private int defaultUserIndex = -1;

        public void setUsers(List<UserEntry> newUsers) {
            users.clear();
            users.addAll(newUsers);
            if (defaultUserIndex >= users.size()) defaultUserIndex = users.isEmpty() ? -1 : 0;
            fireTableDataChanged();
        }

        public int getDefaultUserIndex() {
            return defaultUserIndex;
        }

        public void setDefaultUserIndex(int index) {
            this.defaultUserIndex = index;
            fireTableDataChanged();
        }

        public List<UserEntry> getUsers() {
            return new ArrayList<>(users);
        }

        public void addUser(UserEntry ue) {
            users.add(ue);
            if (defaultUserIndex == -1) defaultUserIndex = 0;
            fireTableRowsInserted(users.size() - 1, users.size() - 1);
        }

        public void removeUser(int row) {
            if (row >= 0 && row < users.size()) {
                users.remove(row);
                if (defaultUserIndex == row) {
                    defaultUserIndex = users.isEmpty() ? -1 : 0;
                } else if (defaultUserIndex > row) {
                    defaultUserIndex--;
                }
                fireTableRowsDeleted(row, row);
            }
        }

        @Override
        public int getRowCount() {
            return users.size();
        }

        @Override
        public int getColumnCount() {
            return columns.length;
        }

        @Override
        public String getColumnName(int column) {
            return columns[column];
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            UserEntry ue = users.get(rowIndex);
            switch (columnIndex) {
                case 0:
                    return rowIndex == defaultUserIndex;
                case 1:
                    return ue.getPrincipal();
                case 2:
                    return ue.hasPassword() ? "*******" : "";
                case 3:
                    return ue.getHeaderSelectorValue();
                case 4:
                    return ue.isEnabled();
                default:
                    return "";
            }
        }

        @Override
        public boolean isCellEditable(int rowIndex, int columnIndex) {
            return columnIndex != 2;
        }

        @Override
        public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
            UserEntry ue = users.get(rowIndex);
            switch (columnIndex) {
                case 0:
                    if (Boolean.TRUE.equals(aValue)) {
                        defaultUserIndex = rowIndex;
                        fireTableDataChanged(); // refresh all rows to clear other radios
                    }
                    return;
                case 1:
                    ue.setPrincipal(aValue.toString());
                    break;
                case 3:
                    String newHeader = aValue.toString().trim();
                    if (!newHeader.isEmpty()) {
                        for (int i = 0; i < users.size(); i++) {
                            if (i != rowIndex && newHeader.equals(users.get(i).getHeaderSelectorValue())) {
                                JOptionPane.showMessageDialog(KerberAuthExtension.suiteFrame(),
                                    "Header selector '" + newHeader + "' is already used by user '" + users.get(i).getUsername() + "'.",
                                    "Duplicate Header Selector", JOptionPane.ERROR_MESSAGE);
                                return;
                            }
                        }
                    }
                    ue.setHeaderSelectorValue(newHeader);
                    break;
                case 4:
                    if (Boolean.TRUE.equals(aValue) && !ue.hasPassword()) {
                        JOptionPane.showMessageDialog(KerberAuthExtension.suiteFrame(),
                            "Cannot enable user '" + ue.getUsername() + "' without a password. Use 'Change Password' first.",
                            "No Password", JOptionPane.WARNING_MESSAGE);
                        return;
                    }
                    ue.setEnabled(Boolean.TRUE.equals(aValue));
                    break;
            }
            fireTableCellUpdated(rowIndex, columnIndex);
            syncToUserManager();
        }

        @Override
        public Class<?> getColumnClass(int columnIndex) {
            if (columnIndex == 0 || columnIndex == 4) return Boolean.class;
            return String.class;
        }
    }
}
