import java.awt.Rectangle;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;

import javax.swing.*;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import java.io.*;
import java.nio.file.*;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import static javax.swing.JOptionPane.*;

public class Launch2 extends javax.swing.JFrame {

  //Variables disponibles en todas mis vistas
  public PcapIf deviceSelected;
  public boolean isFile;
  public boolean isInfinite;
  public int timeout;
  public int numPaquetes;
  public String filtro;
  public String nombreArchivo;
  public StringBuilder errbuf = new StringBuilder();
  public arpform arp;

  //Variable propias de este frame
  private short progresoConfiguracion = 0;
  private List<PcapIf> interfaces;
  private List<String> listaInt;
  private JButton btnArp;

  public Launch2() {
        /*Inicialización de las variables importantes*/
    isFile = false;
    timeout = 0;
    numPaquetes = 0;
    filtro = "";
        /*Obteniendo las interfaces por medio de PcapIf*/
    interfaces = new ArrayList<PcapIf>();
    listaInt = new ArrayList<String>();
    //esta variable r es utilizada para seleccionar la interface en el protocolo ARP
    int r = Pcap.findAllDevs(interfaces, errbuf);
    if (r == Pcap.NOT_OK || interfaces.isEmpty()) {
      System.err.printf("Como quieres conectarte si no tienes ninguna interfaz");
      return;
    }
    //Llenando las lista con las interfaces encontradas
    int i = 0;
    try {
      for (PcapIf device : interfaces) {
        String description = (device.getDescription() != null) ? device.getDescription() : "No description available";
        final byte[] mac = device.getHardwareAddress();
        String dir_mac = (mac == null) ? "No tiene direccion MAC" : asString(mac);
        //Agregando cada interfaz al modelo
        listaInt.add(i, device.getName() + " " + description + ": " + dir_mac);
        i++;
      }//for
    } catch (Exception e) {
      e.toString();
    }
        /*Creando un arreglo de tipo final con las interfaces antes encontradas,
      es necesario por la implementación de una clase anonima al llenar el JList
         */
    String[] a = new String[listaInt.size()];
    a = listaInt.toArray(a);
        /*Creando los componentes, si algún elemento grafico es llenado dinámicamente
      su contenido debe ser declarado antes de este punto*/
    initComponents(a);

    //Agregando RadioButtons ya creados a su ButtonGroup correspondiente
    buttonGroup1.add(rdAire);
    buttonGroup1.add(rdArchivo);
        /*
    Estableciendo limites para el progressBar ya creado
    Teniendo en cuenta 6 pasos para poder comenzar el analisis de paquetes
    */
    pgConfiguracion.setMaximum(6);
    pgConfiguracion.setMinimum(0);

    //agregar el boton de arp
    btnArp = new JButton();
    btnArp.setText("ARP");
    btnArp.setBounds(new Rectangle(80,30));
    btnArp.setLocation(430, 400);
    btnArp.setVisible(true);
    btnArp.addActionListener(new ActionListener(){
      public void actionPerformed(ActionEvent evt) {
        arp = new arpform();
        arp.muestraArp();


      }
    });

    add(btnArp);

    this.setLocationRelativeTo(this);
  }
  // <editor-fold defaultstate="collapsed" desc="Generated Code">
  private void initComponents(String[] a) {


    buttonGroup1 = new javax.swing.ButtonGroup();
    lblEscom = new javax.swing.JLabel();
    lblTitulo = new javax.swing.JLabel();
    rdAire = new javax.swing.JRadioButton();
    rdArchivo = new javax.swing.JRadioButton();
    jLabel5 = new javax.swing.JLabel();
    jLabel6 = new javax.swing.JLabel();
    jLabel7 = new javax.swing.JLabel();
    jLabel8 = new javax.swing.JLabel();
    tpFuentePaquetes = new javax.swing.JTabbedPane();
    fcPaquetes = new javax.swing.JFileChooser();
    jScrollPane1 = new javax.swing.JScrollPane();
    listInterfaces = new javax.swing.JList();
    jLabel11 = new javax.swing.JLabel();
    jSeparator1 = new javax.swing.JSeparator();
    btnComenzar = new javax.swing.JButton();
    jLabel4 = new javax.swing.JLabel();
    jTextField1 = new javax.swing.JTextField("tcp");
    txBytes = new javax.swing.JFormattedTextField(new Integer(65536));
    lblConfiguracion = new javax.swing.JLabel();
    pgConfiguracion = new javax.swing.JProgressBar();
    jSeparator2 = new javax.swing.JSeparator();
    jSeparator3 = new javax.swing.JSeparator();
    jSeparator4 = new javax.swing.JSeparator();
    jLabel1 = new javax.swing.JLabel();
    jLabel2 = new javax.swing.JLabel();
    jTextField2 = new javax.swing.JFormattedTextField(new Integer(10));
    jTextField2.addFocusListener(new java.awt.event.FocusAdapter() {
      public void focusLost(java.awt.event.FocusEvent evt) {
        timeoutOut(evt);
      }
    });
    jcbSegundos = new javax.swing.JComboBox();
    jLabel3 = new javax.swing.JLabel();
    jTextField3 = new javax.swing.JFormattedTextField(new Integer(10));
    jTextField3.addFocusListener(new java.awt.event.FocusAdapter() {
      public void focusLost(java.awt.event.FocusEvent evt) {
        paquetesOut(evt);
      }
    });
    jcbInfinite = new javax.swing.JCheckBox();
    jMenuBar1 = new javax.swing.JMenuBar();
    jMenu1 = new javax.swing.JMenu();
    jMenu2 = new javax.swing.JMenu();

    setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);

    lblEscom.setText("ESCOM | IPN");

    lblTitulo.setText("Weird Shark");

    rdAire.setText("jRadioButton1");
    rdAire.setActionCommand("rbAire");
    rdAire.addActionListener(new java.awt.event.ActionListener() {
      public void actionPerformed(java.awt.event.ActionEvent evt) {
        rdAireActionPerformed(evt);
      }
    });

    rdArchivo.setText("jRadioButton2");
    rdArchivo.setActionCommand("rbArchivo");
    rdArchivo.addActionListener(new java.awt.event.ActionListener() {
      public void actionPerformed(java.awt.event.ActionEvent evt) {
        rdArchivoActionPerformed(evt);
      }
    });

    jLabel5.setText("Modo de captura:");

    jLabel6.setText("Paquetes al aire");

    jLabel7.setText("Lectura de un archivo");
    jLabel8.setText("Bytes capturados:");

    tpFuentePaquetes.addTab("Selección de archivo", fcPaquetes);

        /*Llenando la ista de interfaces*/
    errbuf = new StringBuilder();
    int r = Pcap.findAllDevs(interfaces, errbuf);
    if (r == Pcap.NOT_OK || interfaces.isEmpty()) {
      System.err.printf("Como quieres conectarte si no tienes ninguna interfaz");
      return;
    }
    listInterfaces.setModel(new javax.swing.AbstractListModel() {
      //Creando la lista a partir del model que contiene a las interfaces
      String[] strings = a;

      public int getSize() {
        return strings.length;
      }

      public Object getElementAt(int i) {
        return strings[i];
      }
    });
    listInterfaces.addMouseListener(new java.awt.event.MouseAdapter() {
      public void mouseClicked(java.awt.event.MouseEvent evt) {
        listaClic(evt);
      }
    });
    jScrollPane1.setViewportView(listInterfaces);

    tpFuentePaquetes.addTab("Interfaces de red", jScrollPane1);

    jLabel11.setText("Configuración:");

    btnComenzar.setText("Comenzar");
    btnComenzar.addActionListener(new java.awt.event.ActionListener() {
      public void actionPerformed(java.awt.event.ActionEvent evt) {
        if (rdAire.isSelected() || rdArchivo.isSelected()) {
          if (rdAire.isSelected() && listInterfaces.isSelectionEmpty()) {
            JOptionPane.showMessageDialog(null, "Selecciona una interfaz de red", "Error", ERROR_MESSAGE);
          } else {
            btnComenzarActionPerformed(evt);
          }
        } else {
          JOptionPane.showMessageDialog(null, "Selecciona un modo de captura", "Error", ERROR_MESSAGE);
        }

      }
    });
    jLabel4.setText("Filtro:");

    lblConfiguracion.setText("Configuración Inicial");

    jLabel1.setText("Timeout - ");

    jLabel2.setText("No. paquetes - ");

    jcbSegundos.setModel(new javax.swing.DefaultComboBoxModel(new String[]{"Segundos", "Milisegundos"}));

    jLabel3.setText("Infinite loop - ");

    jcbInfinite.setText("Ignorar No. paquetes");

    jMenu1.setText("File");
    jMenuBar1.add(jMenu1);

    jMenu2.setText("Edit");
    jMenuBar1.add(jMenu2);

    fcPaquetes.addActionListener(new java.awt.event.ActionListener() {
      public void actionPerformed(java.awt.event.ActionEvent evt) {
        fileSelection(evt);
      }
    });

    setJMenuBar(jMenuBar1);
    javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
    getContentPane().setLayout(layout);
    layout.setHorizontalGroup(
      layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
        .addGroup(layout.createSequentialGroup()
          .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
              .addContainerGap()
              .addComponent(jSeparator3, javax.swing.GroupLayout.PREFERRED_SIZE, 311, javax.swing.GroupLayout.PREFERRED_SIZE))
            .addGroup(layout.createSequentialGroup()
              .addGap(27, 27, 27)
              .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                .addComponent(jTextField1)
                .addComponent(jSeparator2)
                .addComponent(jSeparator4)
                .addGroup(layout.createSequentialGroup()
                  .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                      .addComponent(jLabel8)
                      .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                      .addComponent(txBytes, javax.swing.GroupLayout.PREFERRED_SIZE, 88, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addGroup(layout.createSequentialGroup()
                      .addComponent(btnComenzar)
                      .addGap(18, 18, 18))
                    .addComponent(lblEscom)
                    .addComponent(jLabel4)
                    .addGroup(layout.createSequentialGroup()
                      .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                        .addComponent(jLabel1)
                        .addComponent(jLabel11))
                      .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                      .addComponent(jTextField2, javax.swing.GroupLayout.PREFERRED_SIZE, 71, javax.swing.GroupLayout.PREFERRED_SIZE)
                      .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                      .addComponent(jcbSegundos, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addGroup(layout.createSequentialGroup()
                      .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                        .addComponent(jLabel3)
                        .addComponent(jLabel2))
                      .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                      .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                        .addComponent(jcbInfinite)
                        .addGroup(layout.createSequentialGroup()
                          .addComponent(jTextField3)
                          .addGap(57, 57, 57))))
                    .addComponent(jLabel5)
                    .addGroup(layout.createSequentialGroup()
                      .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING, false)
                        .addComponent(rdArchivo, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.PREFERRED_SIZE, 1, Short.MAX_VALUE)
                        .addComponent(rdAire, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.PREFERRED_SIZE, 22, javax.swing.GroupLayout.PREFERRED_SIZE))
                      .addGap(18, 18, 18)
                      .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                        .addComponent(jLabel7)
                        .addComponent(jLabel6))))
                  .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 96, Short.MAX_VALUE)))))
          .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
              .addGap(21, 21, 21)
              .addComponent(lblTitulo)
              .addGap(140, 140, 140)
              .addComponent(lblConfiguracion)
              .addGap(18, 18, 18)
              .addComponent(pgConfiguracion, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
              .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
              .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
              .addComponent(tpFuentePaquetes, javax.swing.GroupLayout.PREFERRED_SIZE, 487, javax.swing.GroupLayout.PREFERRED_SIZE)
              .addContainerGap())))
        .addComponent(jSeparator1)
    );
    layout.setVerticalGroup(
      layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
        .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
          .addContainerGap()
          .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
              .addComponent(lblEscom)
              .addComponent(lblTitulo)
              .addComponent(lblConfiguracion))
            .addComponent(pgConfiguracion, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
          .addGap(10, 10, 10)
          .addComponent(jSeparator1, javax.swing.GroupLayout.PREFERRED_SIZE, 9, javax.swing.GroupLayout.PREFERRED_SIZE)
          .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
              .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
              .addComponent(jLabel5)
              .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
              .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                .addComponent(rdAire)
                .addComponent(jLabel6))
              .addGap(11, 11, 11)
              .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                .addComponent(rdArchivo)
                .addComponent(jLabel7))
              .addGap(12, 12, 12)
              .addComponent(jSeparator2, javax.swing.GroupLayout.PREFERRED_SIZE, 10, javax.swing.GroupLayout.PREFERRED_SIZE)
              .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
              .addComponent(jLabel11)
              .addGap(18, 18, 18)
              .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                .addComponent(jLabel1)
                .addComponent(jTextField2, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addComponent(jcbSegundos, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
              .addGap(18, 18, 18)
              .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                .addComponent(jLabel2)
                .addComponent(jTextField3, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
              .addGap(9, 9, 9)
              .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                .addComponent(jLabel3)
                .addComponent(jcbInfinite, javax.swing.GroupLayout.PREFERRED_SIZE, 18, javax.swing.GroupLayout.PREFERRED_SIZE))
              .addGap(18, 18, 18)
              .addComponent(jSeparator3, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
              .addGap(22, 22, 22)
              .addComponent(jLabel4)
              .addGap(18, 18, 18)
              .addComponent(jTextField1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
              .addGap(18, 18, 18)
              .addComponent(jSeparator4, javax.swing.GroupLayout.PREFERRED_SIZE, 10, javax.swing.GroupLayout.PREFERRED_SIZE)
              .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
              .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                .addComponent(jLabel8)
                .addComponent(txBytes, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
              .addGap(29, 29, 29)
              .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                .addComponent(btnComenzar))
              .addGap(46, 46, 46))
            .addGroup(layout.createSequentialGroup()
              .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
              .addComponent(tpFuentePaquetes, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
              .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))))
    );
    pack();
  }// </editor-fold>

  //Bind entre los radio buttons y el tab para elegir un archivo o una interfaz de red
  private void rdAireActionPerformed(java.awt.event.ActionEvent evt) {
    if (rdAire.isSelected()) {
      tpFuentePaquetes.setSelectedIndex(1);
      tpFuentePaquetes.setEnabledAt(0, false);
      isFile = false;
    }
    progresoConfiguracion = 1;
    pgConfiguracion.setValue(progresoConfiguracion);
  }

  private void rdArchivoActionPerformed(java.awt.event.ActionEvent evt) {
    if (rdArchivo.isSelected()) {
      tpFuentePaquetes.setSelectedIndex(0);
      tpFuentePaquetes.setEnabledAt(1, false);
      isFile = true;
    }
    progresoConfiguracion = 1;
    pgConfiguracion.setValue(progresoConfiguracion);
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

  /*Metodo para saber que elemento de la JList correspondiente a las interfaces fue seleccionado
* el resultado se guarda en una variable PcapIf para ser usado después
* una vez que se elige una interfaz, la lista se deshabilita y se aumenta el progress bar*/
  private void listaClic(java.awt.event.MouseEvent evt) {
    if (listInterfaces.getSelectedIndex() != -1) {
      //Selection, enable filter
      deviceSelected = interfaces.get(listInterfaces.getSelectedIndex());

            /*int snaplen = 64 * 1024;           // Capture all packets, no trucation
        int flags = Pcap.MODE_PROMISCUOUS; // capture all packets
        int timeout = 10 * 1000;           // 10 seconds in millis
        pcap = Pcap.openLive(deviceSelected.getName(), snaplen, flags, timeout, errbuf);*/
      progresoConfiguracion = 2;
      pgConfiguracion.setValue(progresoConfiguracion);
      listInterfaces.setEnabled(false);

    }
  }

  /*Metodo para verificar la asignación del Timeout usado por Pcap*/
  private void timeoutOut(java.awt.event.FocusEvent evt) {
    progresoConfiguracion = 3;
    pgConfiguracion.setValue(progresoConfiguracion);
    if ((int) jTextField2.getValue() < 0) {
      jTextField2.setValue(10);
    }
  }

  /*Metodo para verificar la asignación del número del paquetes a capturar*/
  private void paquetesOut(java.awt.event.FocusEvent evt) {
    progresoConfiguracion = 4;
    pgConfiguracion.setValue(progresoConfiguracion);
    if ((int) jTextField3.getValue() < 0) {
      jTextField3.setValue(100);
    }
  }

  /*Metodo usado para obtener la ruta de un archivo que sera usado por Pcap para analizar sus paquetes*/
  private void fileSelection(java.awt.event.ActionEvent evt) {
    Date id =  new Date();
    File archivo = fcPaquetes.getSelectedFile();
    nombreArchivo = "temp"+id.getTime()+".pcap";

    File receptor  =  new File(nombreArchivo);
    try {
      copyFileUsingStream(archivo,receptor);
    } catch (IOException e) {
      e.printStackTrace();
    }
  }

  private static void copyFileUsingStream(File source, File dest) throws IOException {
    InputStream is = null;
    OutputStream os = null;
    try {
      is = new FileInputStream(source);
      os = new FileOutputStream(dest);
      byte[] buffer = new byte[1024];
      int length;
      while ((length = is.read(buffer)) > 0) {
        os.write(buffer, 0, length);
      }
    } finally {
      is.close();
      os.close();
    }
  }
  /*Metodo para recopilar los datos finales de configuración y pasar al siguiente frame que realizará
* la conexión con Pcap*/
  private void btnComenzarActionPerformed(java.awt.event.ActionEvent evt) {
    //Viendo si se tiene un loop infinito
    isInfinite = jcbInfinite.isSelected();
    filtro = jTextField1.getText();
    numPaquetes = (int) jTextField3.getValue();
    //Poniendo por default 100 paquetes capturados
    if (numPaquetes == 0) {
      numPaquetes = 100;
    }
    //viendo el timeout con segundos o milisegundos
    timeout = (int) jTextField2.getValue();
    if (jcbSegundos.getSelectedIndex() == 0) {
      //milisegundos
      //Poniendo por default 10 segundos
      if (timeout == 0) {
        timeout = 10000; //10 segundos
      } else {
        timeout = timeout * 1000;
      }
    }
    System.out.println("filtro: " + filtro + " INFINITE: " + isInfinite + " isFile: " + isFile + " timeout: " + timeout + " num: " + numPaquetes
      + " nombreArchivo: " + nombreArchivo);
    System.out.println("Interfaz: " + deviceSelected);
    new Protocolos(deviceSelected, timeout, numPaquetes, isFile, isInfinite, filtro, nombreArchivo).setVisible(true);
    if(isFile==true){
      isInfinite =  true;
    }
    this.setVisible(false);
  }

  public static void main(String args[]) {
        /* Set the Nimbus look and feel */
    //<editor-fold defaultstate="collapsed" desc=" Look and feel setting code (optional) ">
        /* If Nimbus (introduced in Java SE 6) is not available, stay with the default look and feel.
         * For details see http://download.oracle.com/javase/tutorial/uiswing/lookandfeel/plaf.html
         */
    try {
      for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels()) {
        if ("Nimbus".equals(info.getName())) {
          javax.swing.UIManager.setLookAndFeel(info.getClassName());
          break;
        }
      }
    } catch (ClassNotFoundException ex) {
      java.util.logging.Logger.getLogger(Launch2.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
    } catch (InstantiationException ex) {
      java.util.logging.Logger.getLogger(Launch2.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
    } catch (IllegalAccessException ex) {
      java.util.logging.Logger.getLogger(Launch2.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
    } catch (javax.swing.UnsupportedLookAndFeelException ex) {
      java.util.logging.Logger.getLogger(Launch2.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
    }
    //</editor-fold>
    //</editor-fold>

    java.awt.EventQueue.invokeLater(new Runnable() {
      public void run() {
        new Launch2().setVisible(true);
      }
    });
  }

  // Variables declaration - do not modify
  private javax.swing.JButton btnComenzar;
  private javax.swing.ButtonGroup buttonGroup1;
  private javax.swing.JFileChooser fcPaquetes;
  private javax.swing.JLabel jLabel1;
  private javax.swing.JLabel jLabel11;
  private javax.swing.JLabel jLabel2;
  private javax.swing.JLabel jLabel3;
  private javax.swing.JLabel jLabel4;
  private javax.swing.JLabel jLabel5;
  private javax.swing.JLabel jLabel6;
  private javax.swing.JLabel jLabel7;
  private javax.swing.JLabel jLabel8;
  private javax.swing.JMenu jMenu1;
  private javax.swing.JMenu jMenu2;
  private javax.swing.JMenuBar jMenuBar1;
  private javax.swing.JScrollPane jScrollPane1;
  private javax.swing.JSeparator jSeparator1;
  private javax.swing.JSeparator jSeparator2;
  private javax.swing.JSeparator jSeparator3;
  private javax.swing.JSeparator jSeparator4;
  private javax.swing.JTextField jTextField1;
  private javax.swing.JFormattedTextField jTextField2;
  private javax.swing.JFormattedTextField jTextField3;
  private javax.swing.JCheckBox jcbInfinite;
  private javax.swing.JComboBox jcbSegundos;
  private javax.swing.JLabel lblConfiguracion;
  private javax.swing.JLabel lblEscom;
  private javax.swing.JLabel lblTitulo;
  private javax.swing.JList listInterfaces;
  private javax.swing.JProgressBar pgConfiguracion;
  private javax.swing.JRadioButton rdAire;
  private javax.swing.JRadioButton rdArchivo;
  private javax.swing.JTabbedPane tpFuentePaquetes;
  private javax.swing.JFormattedTextField txBytes;
  // End of variables declaration
}
