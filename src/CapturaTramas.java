import org.jnetpcap.Pcap;
import org.jnetpcap.PcapBpfProgram;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;

public class CapturaTramas {

    public Pcap pcap;
    private String selectedName;
    private int snaplen;
    private int timeout;
    private String filtro;
    private String nombreArchivo;
    private StringBuilder errbuf = new StringBuilder();
    private boolean isFile;

    public CapturaTramas(String selectedName, int snaplen, int timeout, String filtro) {
        this.selectedName = selectedName;
        this.snaplen = snaplen;
        this.timeout = timeout;
        this.filtro = filtro;
        this.isFile = false;
    }
    public CapturaTramas(String nombreArchivo){
      this.isFile =  true;
      this.nombreArchivo = nombreArchivo;
      System.out.println("Constructor de archivo");
    }
    /*Metodo para la conexion de Pcap a una interfaz*/
    public void conectarPcap() {
      if(isFile==true){
        pcap = Pcap.openOffline(nombreArchivo, errbuf);
        System.out.println("Offline");
      }else {
        System.out.println(
          "s: " + selectedName + " sna: " + snaplen + " prom: " + Pcap.MODE_PROMISCUOUS + "" +
            " t: " + timeout + " err: " + errbuf);
        pcap = Pcap.openLive(selectedName, snaplen, Pcap.MODE_PROMISCUOUS, timeout, errbuf);
        if (pcap == null) {
          System.err.printf("Error while opening device for capture: " + errbuf.toString());
          return;
        }//if
        System.out.println("Conexion realizada");
        crearFiltro();
      }
    }

    /*Metodo para agregar el filtro a dicha conexión ya creada*/
    public void crearFiltro() {
     /*Estableciendo el filtro*/
        PcapBpfProgram filter = new PcapBpfProgram();
        String expression = filtro;
        int optimize = 0;
        int netmask = 0;
        int exito = pcap.compile(filter, expression, optimize, netmask);
        if (exito != Pcap.OK) {
            System.out.println("Filter error: " + pcap.getErr());
        }
        pcap.setFilter(filter);
        System.out.println("Filtro activado");
    }

    /*Metodo para capturar un paquete de la red a la que pcap esta conectada,
    * este metodo caputará un paquete a la vez, y será llamado multiples veces*/
    public AnalisisTrama obtenerPaquete() {
    /*Cada paquete analizado será analizado a través de una instancia de la clase analisis trama
      Creamos una variable final para poder acceder dentro del handler a ella*/
        final AnalisisTrama tramaAnalisis = new AnalisisTrama();
        //Acciones a emprender cada que se captura un paquete
        PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {
            @Override
            public void nextPacket(PcapPacket packet, String user) {
                tramaAnalisis.setPaqueteActual(packet);
            }
        };
        pcap.loop(1, jpacketHandler, "Entrando");
        return tramaAnalisis;
    }

    /*Metodo para pausar la rececpción de paquetes*/
    public void pausarObtenecion() {
      pcap.close();
    }
}
//axelernesto@gmail.com
