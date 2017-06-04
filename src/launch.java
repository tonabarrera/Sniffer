import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;

import javax.swing.*;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

/**
 * Created by Juan Castillo on 03/06/2017.
 */
public class launch extends JPanel implements ListSelectionListener{
  public Pcap pcap;
  public PcapIf deviceSelected;
  private StringBuilder errbuf;
  private int idInterfaz = 0;
  private JList list;
  private DefaultListModel listModel;
  private List<PcapIf> interfaces;
  private JLabel estado;
  private launch(){
    //Estableciendo grilla de tipo border layout
    super(new BorderLayout());
    //Creando los labels
    estado = new JLabel("Obteniendo las interfaces de red, selecciona una");
    //Creando modelo con el que se llenará la lista final
    listModel =  new DefaultListModel();
     /*Lectura de las interfaces de red para llenar el JList del frame principal*/
    interfaces = new ArrayList<PcapIf>();
     errbuf = new StringBuilder();
    int r = Pcap.findAllDevs(interfaces, errbuf);
    if (r == Pcap.NOT_OK || interfaces.isEmpty()) {
      System.err.printf("Como quieres conectarte si no tienes ninguna interfaz");
      return;
    }
    int i = 0;
    try {
      for (PcapIf device : interfaces) {
        String description = (device.getDescription() != null) ? device.getDescription() : "No description available";
        final byte[] mac = device.getHardwareAddress();
        String dir_mac = (mac == null) ? "No tiene direccion MAC" : asString(mac);
        //Agregando cada interfaz al modelo
        listModel.addElement(i+" "+device.getName()+" "+description+": "+dir_mac+" ");
        i++;
      }//for
    } catch (Exception e) {
      e.toString();
    }
    //Creando la lista a partir del model que contiene a las interfaces
    list = new JList(listModel);
    list.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
    list.addListSelectionListener(this);
    list.setVisibleRowCount(5);
    //Agregando nuestra lista a un scroll pane para visualizarla
    JScrollPane listScrollPane = new JScrollPane(list);
    //Agregando un panel para una etiqueta de estado
    JPanel estadoPanel = new JPanel();
    estadoPanel.add(estado);
    estadoPanel.setLayout(new BoxLayout(estadoPanel,BoxLayout.LINE_AXIS));
    //Agregando los paneles al frame
    add(listScrollPane, BorderLayout.CENTER);
    add(estadoPanel, BorderLayout.PAGE_END);
  }


  private static void createAndShowGUI() {
    //Create and set up the window.
    JFrame frame = new JFrame("Launch");
    frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

    //Create and set up the content pane.
    JComponent newContentPane = new launch();
    newContentPane.setOpaque(true); //content panes must be opaque
    frame.setContentPane(newContentPane);
    //Display the window.
    frame.pack();
    frame.setVisible(true);
  }
  private static String asString(final byte[] mac) {
    final StringBuilder buf = new StringBuilder();
    for (byte b : mac) {
      if (buf.length() != 0) {
        buf.append(':');
      }
      if (b >= 0 && b < 16) {
        buf.append('0');
      }
      buf.append(Integer.toHexString((b < 0) ? b + 256 : b).toUpperCase());
    }
    return buf.toString();
  }
  //This method is required by ListSelectionListener.
  public void valueChanged(ListSelectionEvent e) {
    if (e.getValueIsAdjusting() == false) {
      if (list.getSelectedIndex() != -1) {
        //Selection, enable filter
        deviceSelected = interfaces.get(list.getSelectedIndex());

        int snaplen = 64 * 1024;           // Capture all packets, no trucation
        int flags = Pcap.MODE_PROMISCUOUS; // capture all packets
        int timeout = 10 * 1000;           // 10 seconds in millis

        pcap = Pcap.openLive(deviceSelected.getName(), snaplen, flags, timeout, errbuf);
        list.setEnabled(false);
        System.out.println("conectado");
        estado.setText("Interfaz seleccionada, conexión realizada");
      }
    }
  }
  public static void main(String []args) {
    javax.swing.SwingUtilities.invokeLater(new Runnable() {
      public void run() {
        createAndShowGUI();
      }
    });
  }
}
