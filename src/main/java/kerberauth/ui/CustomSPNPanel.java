package kerberauth.ui;

import kerberauth.config.Config;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

/**
 * Panel for managing custom SPN overrides / hints.
 *
 * Each row maps a hostname to a target SPN (replaces [berserko_spn_hints] from krb5.conf).
 * Accepted target formats:
 *   - Full SPN: HTTP/web.domain.local@DOMAIN.LOCAL
 *   - Hostname + realm: web.domain.local@DOMAIN.LOCAL
 *   - Hostname only: web.domain.local (realm auto-appended)
 */
public class CustomSPNPanel extends JPanel {

    private final JTable spnTable;
    private final SPNTableModel tableModel;
    private final JButton addButton;
    private final JButton removeButton;

    public CustomSPNPanel() {
        super(new BorderLayout(4, 4));

        tableModel = new SPNTableModel();
        spnTable = new JTable(tableModel);
        spnTable.setFillsViewportHeight(true);

        // Limit table to 6 visible rows
        spnTable.setPreferredScrollableViewportSize(new Dimension(
                spnTable.getPreferredScrollableViewportSize().width,
                spnTable.getRowHeight() * 6));

        JScrollPane scrollPane = new JScrollPane(spnTable);

        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        addButton = new JButton("Add Override");
        removeButton = new JButton("Remove Selected");
        buttonPanel.add(addButton);
        buttonPanel.add(removeButton);

        this.add(scrollPane, BorderLayout.CENTER);
        this.add(buttonPanel, BorderLayout.SOUTH);

        addButton.addActionListener(e -> addOverride());
        removeButton.addActionListener(e -> removeSelectedOverride());
    }

    private void addOverride() {
        tableModel.addEntry(new SPNEntry("", ""));
        saveToConfig();
    }

    private void removeSelectedOverride() {
        int row = spnTable.getSelectedRow();
        if (row >= 0) {
            tableModel.removeEntry(row);
            saveToConfig();
        }
    }

    public void loadFromConfig() {
        // Load SPN overrides from Config
        List<SPNEntry> entries = new ArrayList<>();
        for (var e : Config.getInstance().getSpnOverrides().entrySet()) {
            entries.add(new SPNEntry(e.getKey(), e.getValue()));
        }
        tableModel.setEntries(entries);
    }

    public void saveToConfig() {
        // Save SPN overrides back to Config
        Config config = Config.getInstance();
        // Clear and repopulate
        for (var e : new ArrayList<>(config.getSpnOverrides().keySet())) {
            config.removeSpnOverride(e);
        }
        for (SPNEntry entry : tableModel.getEntries()) {
            if (!entry.hostPattern.isBlank() && !entry.customSpn.isBlank()) {
                config.putSpnOverride(entry.hostPattern, entry.customSpn);
            }
        }
    }

    // ----------------------
    // Table Model
    // ----------------------

    private class SPNTableModel extends AbstractTableModel {
        private final String[] columns = {"Hostname", "Target SPN / Hostname"};
        private final List<SPNEntry> entries = new ArrayList<>();

        public void setEntries(List<SPNEntry> newEntries) {
            entries.clear();
            entries.addAll(newEntries);
            fireTableDataChanged();
        }

        public List<SPNEntry> getEntries() {
            return new ArrayList<>(entries);
        }

        public void addEntry(SPNEntry entry) {
            entries.add(entry);
            fireTableRowsInserted(entries.size() - 1, entries.size() - 1);
        }

        public void removeEntry(int row) {
            if (row >= 0 && row < entries.size()) {
                entries.remove(row);
                fireTableRowsDeleted(row, row);
            }
        }

        @Override
        public int getRowCount() {
            return entries.size();
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
            SPNEntry e = entries.get(rowIndex);
            switch (columnIndex) {
                case 0: return e.hostPattern;
                case 1: return e.customSpn;
                default: return "";
            }
        }

        @Override
        public boolean isCellEditable(int rowIndex, int columnIndex) {
            return true;
        }

        @Override
        public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
            SPNEntry e = entries.get(rowIndex);
            switch (columnIndex) {
                case 0: e.hostPattern = aValue.toString(); break;
                case 1: e.customSpn = aValue.toString(); break;
            }
            fireTableCellUpdated(rowIndex, columnIndex);
            saveToConfig();
        }

        @Override
        public Class<?> getColumnClass(int columnIndex) {
            return String.class;
        }
    }

    private static class SPNEntry {
        String hostPattern;
        String customSpn;

        SPNEntry(String hostPattern, String customSpn) {
            this.hostPattern = hostPattern;
            this.customSpn = customSpn;
        }
    }
}
