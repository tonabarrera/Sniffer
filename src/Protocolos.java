import org.jnetpcap.PcapIf;;
import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.util.LinkedList;
import java.util.List;

public class Protocolos extends javax.swing.JFrame {
    /*Declaración de las variable referentes a la capa logica*/
    //Lista para guardar las tramas recibidas con sus respectivos analisis generados en la clase
    // Analisis trama
    private List<AnalisisTrama> analisisTramas;
    //Variable para manipular la trama con la que se trabaja actualmente, permitirá actualizar la
    // UI con datos de esta trama
    private AnalisisTrama tramaActual;

    /*Variables usadas para la conexión a Pcap
    * Estas variables se obtienen mediante los parametros ingresados por el usuario en el frame
    * Launch2*/
    //Interfaz seleccionada
    private PcapIf deviceSelected;
    //Define si la captura de paquetes se realizará mediante una interfaz de red o un archivo
    private boolean isFile;
    //Define si se ignora el campo numPaquetes
    private boolean isInfinite;
    //Timeout seleccionado por el usuario
    private int timeout;
    //Define el numero de paquetes que se desean capturar
    private int numPaquetes;
    //Contiene el filtro especificado por el usuario
    private String filtro;
    //Nombre del archivo a leer para obtener los paquetes, usado solo si isFile=true
    private String nombreArchivo;
    //Variable para capturar cualquier error e imprimirlo como un String
    private StringBuilder errbuf = new StringBuilder();

    /*Variables para conectar la UI con las clases logicas que reciben y analizan paquetes */
    //Instancia con los metodos para conexion, y captura de paquetes
    private CapturaTramas capturador;
    //Variable para controlar el estado de recepcion/pausa de paquetes
    private boolean isReceiving;
    private boolean rememberInfinite;
    //Contructor con los params recibidos del frame anterior
    public Protocolos(PcapIf deviceSelected, int timeout, int numPaquetes, boolean isFile,
            boolean isInfinite, String filtro, String nombreArchivo) {

    /*Recibiendo los parametros del frame anterior*/
        analisisTramas = new LinkedList<>();
        this.deviceSelected = deviceSelected;
        this.isFile = isFile;
        this.isInfinite = isInfinite;
        this.filtro = filtro;
        this.timeout = timeout;
        this.numPaquetes = numPaquetes;
        this.nombreArchivo = nombreArchivo;
        this.isReceiving = true;
        this.rememberInfinite = isInfinite;
    /*Creando la UI*/
        initComponents();
    }

    class MenuActionListener extends Component implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            try {
                System.out.println("Selected: " + e.getActionCommand());
                String nombreArchivo = "captura.pcap"; // por defecto
                JFileChooser file = new JFileChooser();
                int aux = file.showOpenDialog(this);
                if (aux == JFileChooser.APPROVE_OPTION) {
                    nombreArchivo = file.getSelectedFile().getAbsolutePath();
                }
                if (!nombreArchivo.equals("")) {
                    capturador.guardarTramas(numPaquetes, nombreArchivo);
                    JOptionPane.showMessageDialog(null, "Archivo guardado");
                } else {
                    System.out.println("No se pudo");
                    JOptionPane.showMessageDialog(null, "No se pudo guardar =(");

                }
            } catch (Exception error) {
                System.out.println("ERROR");
                JOptionPane.showMessageDialog(null, "Epale, epale ocurrio un error");
            }
        }
    }

  /*Seccion para la creación de la UI, esta sección no debe ser modificada salvo casos muy específicos*/
  private void initComponents() {
    jLabel1 = new javax.swing.JLabel();
    jLabel2 = new javax.swing.JLabel();
    jLabel3 = new javax.swing.JLabel();
    jSeparator1 = new javax.swing.JSeparator();
    txtFiltro = new javax.swing.JTextField();
    btnIniciar = new javax.swing.JToggleButton();
    jScrollPane1 = new javax.swing.JScrollPane();
    tablaPaquetes = new javax.swing.JTable();
    jSeparator2 = new javax.swing.JSeparator();
    jLabel4 = new javax.swing.JLabel();
    jScrollPane2 = new javax.swing.JScrollPane();
    listaAnalisis = new javax.swing.JList();
    jLabel5 = new javax.swing.JLabel();
    jScrollPane3 = new javax.swing.JScrollPane();
    listaOriginal = new javax.swing.JList();
    jMenuBar1 = new javax.swing.JMenuBar();
    jMenu1 = new javax.swing.JMenu();
    jMenu2 = new javax.swing.JMenu();
    menuItem = new javax.swing.JMenuItem();

    setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);

    jLabel1.setText("ESCOM | IPN");

    jLabel2.setText("Weird Shark");

    jLabel3.setText("Filtro");

    btnIniciar.setText("Iniciar");
    btnIniciar.addActionListener(new java.awt.event.ActionListener() {
      public void actionPerformed(java.awt.event.ActionEvent evt) {
        btnIniciarActionPerformed(evt);
      }
    });

    tablaPaquetes.setModel(new javax.swing.table.DefaultTableModel(
      new Object [][] {{}
      },
      new String [] {
        "No.", "Tiempo", "Origen", "Destino","Protocolo","Tamaño","Info"
      }
    ));
    tablaPaquetes.addMouseListener(new java.awt.event.MouseAdapter() {
      public void mouseClicked(java.awt.event.MouseEvent evt) {
        getTrama(evt);
      }
    });
    jScrollPane1.setViewportView(tablaPaquetes);

    jLabel4.setText("Análisis");

    listaAnalisis.setModel(new javax.swing.AbstractListModel() {
      String[] strings = { " ", " ", " ", " ", " " };
      public int getSize() { return strings.length; }
      public Object getElementAt(int i) { return strings[i]; }
    });
    jScrollPane2.setViewportView(listaAnalisis);

    jLabel5.setText("Trama original");

    listaOriginal.setModel(new javax.swing.AbstractListModel() {
      String[] strings = { };
      public int getSize() { return strings.length; }
      public Object getElementAt(int i) { return strings[i]; }
    });

    jScrollPane3.setViewportView(listaOriginal);

    jMenu1.setText("File");
    jMenu1.setMnemonic(KeyEvent.VK_F);
    jMenuBar1.add(jMenu1);

    menuItem.setText("Save");
    menuItem.addActionListener(new MenuActionListener());
    jMenu1.add(menuItem);

    setJMenuBar(jMenuBar1);

    javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
    getContentPane().setLayout(layout);
    layout.setHorizontalGroup(
      layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
        .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
          .addGap(0, 0, Short.MAX_VALUE)
          .addComponent(jSeparator1, javax.swing.GroupLayout.PREFERRED_SIZE, 714, javax.swing.GroupLayout.PREFERRED_SIZE))
        .addComponent(jScrollPane1, javax.swing.GroupLayout.Alignment.TRAILING)
        .addGroup(layout.createSequentialGroup()
          .addComponent(jSeparator2, javax.swing.GroupLayout.PREFERRED_SIZE, 732, javax.swing.GroupLayout.PREFERRED_SIZE)
          .addGap(0, 0, Short.MAX_VALUE))
        .addGroup(layout.createSequentialGroup()
          .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
              .addGap(18, 18, 18)
              .addComponent(jLabel1)
              .addGap(228, 228, 228)
              .addComponent(jLabel2)
              .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
              .addComponent(btnIniciar))
            .addGroup(layout.createSequentialGroup()
              .addGap(19, 19, 19)
              .addComponent(jLabel3)
              .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
              .addComponent(txtFiltro, javax.swing.GroupLayout.PREFERRED_SIZE, 280, javax.swing.GroupLayout.PREFERRED_SIZE)
              .addGap(0, 0, Short.MAX_VALUE))
            .addGroup(layout.createSequentialGroup()
              .addContainerGap()
              .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                .addComponent(jLabel4)
                .addComponent(jScrollPane2, javax.swing.GroupLayout.PREFERRED_SIZE, 341, javax.swing.GroupLayout.PREFERRED_SIZE))
              .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
              .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                .addComponent(jLabel5)
                .addGroup(layout.createSequentialGroup()
                  .addGap(10, 10, 10)
                  .addComponent(jScrollPane3, javax.swing.GroupLayout.PREFERRED_SIZE, 340, javax.swing.GroupLayout.PREFERRED_SIZE)))))
          .addContainerGap())
    );
    layout.setVerticalGroup(
      layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
        .addGroup(layout.createSequentialGroup()
          .addContainerGap()
          .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
            .addComponent(jLabel1)
            .addComponent(jLabel2)
            .addComponent(btnIniciar))
          .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
          .addComponent(jSeparator1, javax.swing.GroupLayout.PREFERRED_SIZE, 10, javax.swing.GroupLayout.PREFERRED_SIZE)
          .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
          .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
            .addGroup(layout.createSequentialGroup()
              .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                .addComponent(jLabel3)
                .addComponent(txtFiltro, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
              .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
              .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 188, javax.swing.GroupLayout.PREFERRED_SIZE)
              .addGap(18, 18, 18)
              .addComponent(jSeparator2, javax.swing.GroupLayout.PREFERRED_SIZE, 10, javax.swing.GroupLayout.PREFERRED_SIZE)
              .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
              .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                .addComponent(jLabel4)
                .addComponent(jLabel5))
              .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
              .addComponent(jScrollPane2, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
            .addComponent(jScrollPane3, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
          .addContainerGap(26, Short.MAX_VALUE))
    );
    pack();
  }
  /*Fin de la creación de la UI*/

    /*Sección para agregar los Event Listeners correspondientes*/
    //Boton - Iniciar: Comienza o termina la recepción de paquetes
    private void btnIniciarActionPerformed(java.awt.event.ActionEvent evt) {
        //Iniciando la recepción de paquetes
        //Lectura de archivo
        if(isFile){
          if(isReceiving == true){
            System.out.println("Iniciando con archivo");
            capturador =  new CapturaTramas(nombreArchivo);
            capturador.conectarPcap();
            AdministradorPaquetes administradorPaquetes = new AdministradorPaquetes();
            administradorPaquetes.start();
            //Para leer el archivo completo
            isInfinite = true;
            //Cambio estado del boton
            isReceiving = false;
          }else{
            isReceiving = true;
          }
        }else{
          System.out.println("Iniciando con captura al aire");
          //Captura al aire
          if (isReceiving == true) {
            //Generando conexión con pcap
            capturador = new CapturaTramas(deviceSelected.getName(), (64 * 1024), timeout, filtro);
            capturador.conectarPcap();
            //Capturando los paquetes mediante el uso de un thread independiente para esto
            AdministradorPaquetes administradorPaquetes = new AdministradorPaquetes();
            administradorPaquetes.start();
            //Realizando un toggle
            isReceiving = false;
            if(rememberInfinite == true){
              isInfinite = true;
            }
          }else {
            //Pausando la obtención de paquetes, mediante el cierre de la conexión
            capturador.pausarObtenecion();
            isReceiving = true;
          }
        }
    }

    //Obteniendo la información de una trama
    private void getTrama(java.awt.event.MouseEvent evt) {
        int indiceTrama = tablaPaquetes.getSelectedRow();
        //Mostrando información
        if (indiceTrama > 0) {
            AnalisisTrama tramaActual = analisisTramas.get(indiceTrama - 1);
            //Llenando lista con la información en hexadecimal de la trama
            byte[] informacionOriginal = tramaActual.getInfoHexadecimal();
            StringBuilder hexadecimal = new StringBuilder();
            DefaultListModel modelo = new DefaultListModel();

            for (int i = 0; i < informacionOriginal.length; i++) {
                hexadecimal.append(String.format("%02X ", informacionOriginal[i]));
                if (i % 10 == 0 && i > 0) {
                    modelo.addElement(hexadecimal.toString());
                    hexadecimal.setLength(0);
                }
            }
            listaOriginal.setModel(modelo);



            if (tramaActual.getProtocolo().equals("Ipv4")) {
                mostarProtocoloIPv4(tramaActual);
                listaAnalisis.setModel(modelo);
            } else if (tramaActual.getProtocolo().equals("UDP")) {
                mostrarProtocoloUDP(tramaActual);
            } else if (tramaActual.getProtocolo().equals("TCP")) {
                mostrarProtocoloTCP(tramaActual);
            }else if(tramaActual.getProtocolo().equals("IGMP")){
                mostrarProtocoloIGMP(tramaActual);
            }else if(tramaActual.getProtocolo().equals("ICMP")){
                mostrarProtocoloICMP(tramaActual);
            }
            else if(tramaActual.getProtocolo().equals("LLC")){
                mostrarProtocoloLLC(tramaActual);
            }
        }
    }
  private void mostrarProtocoloICMP(AnalisisTrama tramaActual){
    StringBuilder informacion =  new StringBuilder();
    DefaultListModel modelo =  new DefaultListModel();
    modelo =  mostarProtocoloIPv4(tramaActual);

    //Agregando el titulo para un paquete ICMP
    informacion.append("---Protocolo ICMP---");
    modelo.addElement(informacion.toString());
    informacion.setLength(0);

    //Agregando el Tipo
    informacion.append("Tipo ICMP: "+tramaActual.getTipoICMP());
    modelo.addElement(informacion.toString());
    informacion.setLength(0);
    //Agregando Codigo
    informacion.append("Codigo: "+tramaActual.getCodigoICMP());
    modelo.addElement(informacion.toString());
    informacion.setLength(0);

    //Agregando Description
    informacion.append("Descripcion: "+tramaActual.getDescripcionICMP());
    modelo.addElement(informacion.toString());
    informacion.setLength(0);

    //Agregando el Checkdsum
    informacion.append("Checkusm: "+tramaActual.getChecksumICMP());
    modelo.addElement(informacion.toString());
    informacion.setLength(0);

    listaAnalisis.setModel(modelo);
  }
  private void mostrarProtocoloIGMP(AnalisisTrama tramaActual){
    StringBuilder informacion = new StringBuilder();
    DefaultListModel modelo = new DefaultListModel();

    informacion.append("--- Protocolo: IGMP ---");
    modelo.addElement(informacion.toString());
    informacion.setLength(0);

    informacion.append(String.format("0x%02X .... = Tipo: %s", tramaActual.getTipoIGMPbyte(),tramaActual.getTipoIGMP()));
    modelo.addElement(informacion.toString());
    informacion.setLength(0);

    informacion.append("Tiempo Max de Respuesta: " + tramaActual.getTiempoRespuesta()+" ds");
    modelo.addElement(informacion.toString());
    informacion.setLength(0);

    informacion.append("Checksum: "+ tramaActual.getChecksumIGMP());
    modelo.addElement(informacion.toString());
    informacion.setLength(0);

    informacion.append("Grupo: " + tramaActual.getGrupo());
    modelo.addElement(informacion.toString());
    informacion.setLength(0);

    listaAnalisis.setModel(modelo);

  }
  /*Declaración de metodos de utilería en la aplicación*/
  /*Retorno el modelo para seguir modificandola ya que casi T0DO es ipv4*/
    private DefaultListModel mostarProtocoloIPv4(AnalisisTrama tramaActual) {
        StringBuilder informacion = new StringBuilder();
        DefaultListModel modelo = new DefaultListModel();

        informacion.append("---- Protocolo: IPv4 ----");
        modelo.addElement(informacion.toString());
        informacion.setLength(0);

        informacion.append(String.format("0%s .... = Version: %d",
                Integer.toBinaryString(tramaActual.getVersion()), tramaActual.getVersion()));
        modelo.addElement(informacion.toString());
        informacion.setLength(0);

        informacion.append(String.format(".... 0%s = Header length: %d bytes (%X)",
                Integer.toBinaryString(tramaActual.getHeaderLength()),
                tramaActual.getHeaderLength() * 4, tramaActual.getHeaderLength()));
        modelo.addElement(informacion.toString());
        informacion.setLength(0);

        informacion.append(String.format("Differentiated services: 0x%02X", tramaActual.getTos()));
        modelo.addElement(informacion.toString());
        informacion.setLength(0);

        informacion.append("Differentiated services Codepoint: " + tramaActual.getTosCode());
        modelo.addElement(informacion.toString());
        informacion.setLength(0);

        informacion.append("Explicit Congestion Notification: " + tramaActual.getTosECN());
        modelo.addElement(informacion.toString());
        informacion.setLength(0);

        informacion.append("Total Length: " + tramaActual.getLength());
        modelo.addElement(informacion.toString());
        informacion.setLength(0);

        informacion.append(String.format("Identifier: 0x%04X (%d)\n", tramaActual.getId(),
                tramaActual.getId()));
        modelo.addElement(informacion.toString());
        informacion.setLength(0);

        informacion.append(String.format("Flags: 0x%02X", tramaActual.getFlags()));
        modelo.addElement(informacion.toString());
        informacion.setLength(0);

        informacion.append(String.format("%d... .... = Reserved Bit: %s set\n",
                tramaActual.getFlagReserved(), (tramaActual.getFlagReserved() == 1 ? "" : "not")));
        modelo.addElement(informacion.toString());
        informacion.setLength(0);
        informacion.append(String.format(".%d.. .... = Don't fragment: %s\n",
                tramaActual.getFlagDF(), tramaActual.getFlagDFDesc()));
        modelo.addElement(informacion.toString());
        informacion.setLength(0);
        informacion.append(String.format("..%d. .... = More fragments: %s\n",
                tramaActual.getFlagMF(), tramaActual.getFlagMFDesc()));
        modelo.addElement(informacion.toString());
        informacion.setLength(0);

        informacion.append("Fragment Offset: " + tramaActual.getOffset());
        modelo.addElement(informacion.toString());
        informacion.setLength(0);

        informacion.append("Time to live: " + tramaActual.getTtl());
        modelo.addElement(informacion.toString());
        informacion.setLength(0);

        informacion.append(String.format("Header Checksum: 0x%04X", tramaActual.getChecksum()));
        modelo.addElement(informacion.toString());
        informacion.setLength(0);

        return modelo;
    }

    private void mostrarProtocoloUDP(AnalisisTrama tramaActual) {
        StringBuilder informacion = new StringBuilder();
        DefaultListModel modelo = new DefaultListModel();

        modelo = mostarProtocoloIPv4(tramaActual);

        informacion.append("---- Protocolo: UDP ----");
        modelo.addElement(informacion.toString());
        informacion.setLength(0);

        informacion.append("Source port: " + tramaActual.getSrcPort());
        modelo.addElement(informacion.toString());
        informacion.setLength(0);

        informacion.append("Destination port: " + tramaActual.getDestPort());
        modelo.addElement(informacion.toString());
        informacion.setLength(0);

        informacion.append("Length: " + tramaActual.getLengthUDP());
        modelo.addElement(informacion.toString());
        informacion.setLength(0);

        informacion.append(String.format("Checksum: 0x%04X", tramaActual.getChecksumUDP()));
        modelo.addElement(informacion.toString());
        informacion.setLength(0);

        listaAnalisis.setModel(modelo);
    }

    private void mostrarProtocoloTCP(AnalisisTrama tramaActual) {
        StringBuilder informacion = new StringBuilder();
        DefaultListModel modelo = new DefaultListModel();

        modelo = mostarProtocoloIPv4(tramaActual);
        informacion.append("---- Protocolo: TCP ----");
        modelo.addElement(informacion.toString());
        informacion.setLength(0);

        informacion.append("Source port: " + tramaActual.getSrcPort());
        modelo.addElement(informacion.toString());
        informacion.setLength(0);

        informacion.append("Destination port: " + tramaActual.getDestPort());
        modelo.addElement(informacion.toString());
        informacion.setLength(0);

        informacion.append("Secuence number: " + tramaActual.getSeq());
        modelo.addElement(informacion.toString());
        informacion.setLength(0);

        informacion.append("Acknowledgment: " + tramaActual.getAck());
        modelo.addElement(informacion.toString());
        informacion.setLength(0);

        informacion.append("Header length: " + tramaActual.getHlenTCP());
        modelo.addElement(informacion.toString());
        informacion.setLength(0);

        informacion.append(String.format("Flags: 0x%03X", tramaActual.getFlags()));
        modelo.addElement(informacion.toString());
        informacion.setLength(0);

        informacion.append(String.format(".... %d... .... = CWR: %s",
                (tramaActual.getFlagCWR() ? 1 : 0), tramaActual.getFlagCWR()));
        modelo.addElement(informacion.toString());
        informacion.setLength(0);

        informacion.append(String.format(".... .%d.. .... = ECN-Echo: %s",
                (tramaActual.getFlagECE() ? 1 : 0), tramaActual.getFlagECE()));
        modelo.addElement(informacion.toString());
        informacion.setLength(0);

        informacion.append(String.format(".... ..%d. .... = Urgent: %s",
                (tramaActual.getFlagURG() ? 1 : 0), tramaActual.getFlagURG()));
        modelo.addElement(informacion.toString());
        informacion.setLength(0);

        informacion.append(String.format(".... ...%d .... = Acknowledgment: %s",
                (tramaActual.getFlagACK() ? 1 : 0), tramaActual.getFlagACK()));
        modelo.addElement(informacion.toString());
        informacion.setLength(0);

        informacion.append(String.format(".... .... %d... = Push: %s",
                (tramaActual.getFlagPSH() ? 1 : 0), tramaActual.getFlagPSH()));
        modelo.addElement(informacion.toString());
        informacion.setLength(0);

        informacion.append(String.format(".... .... .%d.. = Reset: %s",
                (tramaActual.getFlagPSH() ? 1 : 0), tramaActual.getFlagRST()));
        modelo.addElement(informacion.toString());
        informacion.setLength(0);

        informacion.append(String.format(".... .... ..%d. = Syn: %s",
                (tramaActual.getFlagSYN() ? 1 : 0), tramaActual.getFlagSYN()));
        modelo.addElement(informacion.toString());
        informacion.setLength(0);

        informacion.append(String.format(".... .... ...%d = Fin: %s",
                (tramaActual.getFlagFIN() ? 1 : 0), tramaActual.getFlagFIN()));
        modelo.addElement(informacion.toString());
        informacion.setLength(0);

        informacion.append("Window size value: " + tramaActual.getWindow());
        modelo.addElement(informacion.toString());
        informacion.setLength(0);

        informacion.append(String.format("Checksum: 0x%04X", tramaActual.getChecksumTCP()));
        modelo.addElement(informacion.toString());
        informacion.setLength(0);

        informacion.append("Urgent point: " + tramaActual.getUrgent());
        modelo.addElement(informacion.toString());
        informacion.setLength(0);

        listaAnalisis.setModel(modelo);
    }
    private void mostrarProtocoloLLC(AnalisisTrama tramaActual){
        StringBuilder informacion = new StringBuilder();
        DefaultListModel modelo = new DefaultListModel();

        informacion.append("---- Protocolo: LLC ----");
        modelo.addElement(informacion.toString());
        informacion.setLength(0);

        informacion.append(tramaActual.getMACD());
        modelo.addElement(informacion.toString());
        informacion.setLength(0);

        informacion.append(tramaActual.getMACO());
        modelo.addElement(informacion.toString());
        informacion.setLength(0);

        informacion.append("DSAP: "+tramaActual.getDSAP());
        modelo.addElement(informacion.toString());
        informacion.setLength(0);

        informacion.append("SSAP: "+tramaActual.getSSAP());
        modelo.addElement(informacion.toString());
        informacion.setLength(0);

        informacion.append("Control: "+tramaActual.getControl());
        modelo.addElement(informacion.toString());
        informacion.setLength(0);


        informacion.append("Tipo: "+tramaActual.getTipo());
        modelo.addElement(informacion.toString());
        informacion.setLength(0);

        informacion.append("PF: "+tramaActual.getPF());
        modelo.addElement(informacion.toString());
        informacion.setLength(0);

        if(tramaActual.getTipo().equals("Unnumbered")){
            if( tramaActual.getSnrm()== 1){
                informacion.append("Code: SNRM | Respuesta Normal");
                modelo.addElement(informacion.toString());
                informacion.setLength(0);
            }else if(tramaActual.getSnrme() == 204){
                informacion.append("Code: SNRME | Respuesta Normal Extendida");
                modelo.addElement(informacion.toString());
                informacion.setLength(0);
            }else if(tramaActual.getSabm() == 192){
                informacion.append("Code: SABM | Respuesta Asincrona");
                modelo.addElement(informacion.toString());
                informacion.setLength(0);
            }else if(tramaActual.getSabme() == 236){
                informacion.append("Code: SABME | Respuesta Asincrona Extendida");
                modelo.addElement(informacion.toString());
                informacion.setLength(0);
            }else if(tramaActual.getUi() == 0){
                informacion.append("Code: UI | Información sin numerar");
                modelo.addElement(informacion.toString());
                informacion.setLength(0);
            }else if(tramaActual.getUr() == 40){
                informacion.append("Code: UR | UR");
                modelo.addElement(informacion.toString());
                informacion.setLength(0);
            }else if(tramaActual.getDisc() == 8){
                informacion.append("Code: DISC | Desconexión");
                modelo.addElement(informacion.toString());
                informacion.setLength(0);
            }else if(tramaActual.getRst() == 196){
                informacion.append("Code: RSET | Reinicio");
                modelo.addElement(informacion.toString());
                informacion.setLength(0);
            }else if(tramaActual.getXid() == 228){
                informacion.append("Code: XID | Intercambio de ID");
                modelo.addElement(informacion.toString());
                informacion.setLength(0);
            }
        }else if(tramaActual.getTipo().equals("Supervisory")){
            informacion.append(tramaActual.getNR());
            modelo.addElement(informacion.toString());
            informacion.setLength(0);
            informacion.append(tramaActual.getCodigo());
            modelo.addElement(informacion.toString());
            informacion.setLength(0);
        }else{
            informacion.append(tramaActual.getNS());
            modelo.addElement(informacion.toString());
            informacion.setLength(0);

            informacion.append(tramaActual.getNS());
            modelo.addElement(informacion.toString());
            informacion.setLength(0);
        }

        listaAnalisis.setModel(modelo);
    }
    /*Declaración de metodos de utilería en la aplicación*/
    //Metodo para agregar una fila a la JTable, la fila se llena con los valores de trama actual
    private void argegarFila() {
        DefaultTableModel modelo = (DefaultTableModel) tablaPaquetes.getModel();
        /*{numero, tiempo, ipOrigen, ipDestino, Protocolo, Tamaño, Info}*/
        String[] datosPaquete = {String.valueOf(tramaActual.getNumero()), tramaActual.getTiempo(),
                tramaActual.getIpOrigen(), tramaActual.getIpDestino(), tramaActual.getProtocolo(),
                String.valueOf(tramaActual.getTamaño()), tramaActual.getInfo()};
        modelo.addRow(datosPaquete);
    }

    /*Clase Administrador de Paquetes
    * Esta clase permitirá tener un thread destinado unicamente a la recepción de paquetes,
    * de esta manera el thread principal del frame no se ve afectado en su performance
    * */
    class AdministradorPaquetes extends Thread {
        public void run() {
            //Validamos la opcion de conexión elegida
            if (!isInfinite) {
                //Opción: Número de paquetes
                for (int i = 0; i < numPaquetes; i++) {
                    tramaActual = capturador.obtenerPaquete();
                    tramaActual.setNumero(i);
                    tramaActual.analizarPaquete();
                    analisisTramas.add(tramaActual);
                    //Guardar datos en la tabla
                    argegarFila();
                    //guardar en la lista
                }
            } else {
                //Opción: Bucle Infinito
                int i = 0;
                while (isInfinite) {
                    tramaActual = capturador.obtenerPaquete();
                    tramaActual.setNumero(i);
                    try{
                      tramaActual.analizarPaquete();
                    }catch(Exception e){
                      isInfinite =  false;
                      System.out.println("Termine lectura de paquetes");
                    }

                    analisisTramas.add(tramaActual);
                    //Guardar datos en la tabla
                    argegarFila();
                    //guardar en la lista
                    i++;
                }
            }
        }//run()
    }//clase Adminsitrador paquetes

    /*Aregando el look and feel nimbus*/
    public static void main(String args[]) {
        /* Set the Nimbus look and feel */
        try {
            for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager
                    .getInstalledLookAndFeels()) {
                if ("Nimbus".equals(info.getName())) {
                    javax.swing.UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
        } catch (ClassNotFoundException ex) {
            java.util.logging.Logger.getLogger(Protocolos.class.getName()).log(
                    java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(Protocolos.class.getName()).log(
                    java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(Protocolos.class.getName()).log(
                    java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(Protocolos.class.getName()).log(
                    java.util.logging.Level.SEVERE, null, ex);
        }
    }

    //Variables para UI
    private javax.swing.JToggleButton btnIniciar;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JLabel jLabel5;
    private javax.swing.JMenu jMenu1;
    private javax.swing.JMenu jMenu2;
    private javax.swing.JMenuBar jMenuBar1;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JScrollPane jScrollPane2;
    private javax.swing.JScrollPane jScrollPane3;
    private javax.swing.JSeparator jSeparator1;
    private javax.swing.JSeparator jSeparator2;
    private javax.swing.JList listaAnalisis;
    private javax.swing.JList listaOriginal;
    private javax.swing.JTable tablaPaquetes;
    private javax.swing.JTextField txtFiltro;
    private javax.swing.JMenuItem menuItem;
    // End of variables declaration
}
