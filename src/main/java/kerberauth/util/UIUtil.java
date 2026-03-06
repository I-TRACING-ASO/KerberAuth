package kerberauth.util;

import java.awt.Point;
import java.awt.event.MouseWheelEvent;

import javax.swing.JScrollBar;
import javax.swing.JScrollPane;
import javax.swing.SwingUtilities;

public class UIUtil {
    
    public static void installWheelPassthrough(JScrollPane childScrollPane) {
        childScrollPane.addMouseWheelListener(e -> {
            JScrollBar bar = childScrollPane.getVerticalScrollBar();
            if (bar == null) {
                return;
            }

            boolean canScrollInternally = bar.isVisible() && (bar.getMaximum() - bar.getMinimum() > bar.getVisibleAmount());
            if (canScrollInternally) {
                return;
            }

            JScrollPane parentScrollPane = (JScrollPane) SwingUtilities.getAncestorOfClass(JScrollPane.class, childScrollPane.getParent());
            if (parentScrollPane == null) {
                return;
            }

            Point p = SwingUtilities.convertPoint(childScrollPane, e.getPoint(), parentScrollPane);
            MouseWheelEvent forwarded = new MouseWheelEvent(
                parentScrollPane,
                e.getID(),
                e.getWhen(),
                e.getModifiersEx(),
                p.x,
                p.y,
                e.getXOnScreen(),
                e.getYOnScreen(),
                e.getClickCount(),
                e.isPopupTrigger(),
                e.getScrollType(),
                e.getScrollAmount(),
                e.getWheelRotation(),
                e.getPreciseWheelRotation()
            );

            parentScrollPane.dispatchEvent(forwarded);
            e.consume();
        });
    }
    
}
