package kerberauth.ui;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.JOptionPane;

import kerberauth.KerberAuthExtension;

public class HelpButtonActionListener implements ActionListener {

    private String message;

    public HelpButtonActionListener(String m) {
        this.message = m;
    }

    public void actionPerformed(ActionEvent e) {
        JOptionPane.showMessageDialog(
                KerberAuthExtension.suiteFrame(),
                message, "Help",
                JOptionPane.INFORMATION_MESSAGE);
    }
}
