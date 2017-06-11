import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.protocol.network.Arp;
import org.jnetpcap.protocol.network.Icmp;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.network.Ip6;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;

/*En esta clase se realizan las llamadas a las librerias de Jnetpcap para el análisis de un trama
* Cada instancia de esta clase recibe un paquete crudo de Pcap*/
public class AnalisisTrama {
    //Paquete a analizar
    private PcapPacket paqueteActual;
    /*Variables básicas para un paquetes, seran mostradas en la JTable de la clase Protocolos*/
    //Numero es enviado desde un for() que controla numPaquetes
    private int numero;
    //Calculados usando el paquete
    private String tiempo;
    //Usamos la clase Ip4 para obtener estos valores en el metodo calcularIp()
    private String ipOrigen;
    private String ipDestino;

    private String protocolo;
    private int tamaño;
    private String info;
    /*-------Agregar aqui las variable necesarias para cada protocolo-------------*/
  /*Variables para el análisis de protocolos, ordenados por prioridad segun modelo TCP/IP*/
    //Capa Transporte
    private Tcp analizadorTCP;
    private Udp analizadorUDP;
    //Capa Internet
    private Arp analizadorARP;
    private Icmp analizadorICMP;
    private Ip4 analizadorIP4;
    private Ip6 analizadorIP6;
    /*Variables para IPv4*/
    private int version;
    private int headerLength;
    private int tos;
    private int tosCode;
    private int tosECN;
    private int length;
    private int Id;
    private int flags;
    private int flagReserved;
    private int flagDF;
    private int flagMF;
    private String flagDFDesc;
    private String flagMFDesc;
    private int offset;
    private int ttl;
    private int protocoloId;
    private int checksum;
    /*Fin de las variables IPv4*/

    /*Varibles para UDP*/
    private int srcPort; // tambien se usa en TCP
    private int destPort; // tambien se usa en TCP
    private int lengthUDP;
    private int checksumUDP;
    /*Fin de las variables UDP*/

    /*Variables TCP*/
    private long seq;
    private long ack;
    private int hlenTCP;
    private int flagsTCP;
    private boolean flagCWR;
    private boolean flagECE;
    private boolean flagURG;
    private boolean flagACK;
    private boolean flagPSH;
    private boolean flagSYN;
    private boolean flagFIN;
    private boolean flagRST;
    private int window;
    private int checksumTCP;
    private int urgent;
    /*Fin de las variables TCP*/
    //Variables IGMP
    private String tipoIGMP;
    private byte tipoIGMPbyte;
    private byte tiempoRespuesta;
    private String grupo;
    private String checksumIGMP;
    /*Variables ICMP*/
    private int tipoICMP;
    private int codigoICMP;
    private String descripcionICMP;
    private int checksumICMP;

    //Capa Fisica
    private byte[] infoHexadecimal;

    //Capa Fisica
    public AnalisisTrama() {
        analizadorIP4 = new Ip4();
        analizadorIP6 = new Ip6();
        analizadorARP = new Arp();
        analizadorICMP = new Icmp();
        analizadorTCP = new Tcp();
        analizadorUDP = new Udp();
    }

    /*Analizando el paquete actual*/
    //Este paquete analiza un paquete de forma general, además de analizarlo de acuerdo a su
    //protocolo particular, los resultados de la analisis con guardados en sus variables
    // correspondientes
    //para despues acceder a ellos a traves de sus getters en el frame de protocolos.
    public void analizarPaquete() {
        //Análisis de datos generales, los cuales iran en el JTable
        tiempo = obtenerFecha();
        tamaño = paqueteActual.getTotalSize();
        info = asString(paqueteActual.getByteArray(0, 5)) + "...";
        //Calculando ipOrigen e ipDestino
        calcularIp();
        //Copiando info en hexadecimal
        accederHexadecimal();
        //Obteniendo protocolo usado + Análisis de protocolos
        if (paqueteActual.hasHeader(analizadorIP4)) {
            //Análisis del IPv4 agregar codigo para el analisis aqui
            if (paqueteActual.getHeader(analizadorIP4).type() == 2) {
                protocolo = "IGMP";
                AnalizarIGMP();
            } else {
                protocolo = "Ipv4";
                setVersion(analizadorIP4.version());
                setHeaderLength(analizadorIP4.hlen());
                setTos(analizadorIP4.tos());
                setTosCode(analizadorIP4.tos_Codepoint());
                setTosECN(analizadorIP4.tos_ECN());
                setLength(analizadorIP4.length());
                setId(analizadorIP4.id());
                setFlags(analizadorIP4.flags());
                setFlagReserved(analizadorIP4.flags_Reserved());
                setFlagDF(analizadorIP4.flags_DF());
                setFlagMF(analizadorIP4.flags_MF());
                setFlagDFDesc(analizadorIP4.flags_DFDescription());
                setFlagMFDesc(analizadorIP4.flags_MFDescription());
                setTtl(analizadorIP4.ttl());
                setProtocoloId(analizadorIP4.type());
                setChecksum(analizadorIP4.checksum());
                if (paqueteActual.hasHeader(analizadorUDP)) {
                    protocolo = "UDP";
                    setSrcPort(analizadorUDP.source());
                    setDestPort(analizadorUDP.destination());
                    setLengthUDP(analizadorUDP.length());
                    setChecksumUDP(analizadorUDP.checksum());
                } else if (paqueteActual.hasHeader(analizadorTCP)) {
                    protocolo = "TCP";
                    setSrcPort(analizadorTCP.source());
                    setDestPort(analizadorTCP.destination());
                    setSeq(analizadorTCP.seq());
                    setAck(analizadorTCP.ack());
                    setHlenTCP(analizadorTCP.hlen());
                    setFlagsTCP(analizadorTCP.flags());
                    setFlagACK(analizadorTCP.flags_ACK());
                    setFlagCWR(analizadorTCP.flags_CWR());
                    setFlagECE(analizadorTCP.flags_ECE());
                    setFlagFIN(analizadorTCP.flags_FIN());
                    setFlagPSH(analizadorTCP.flags_PSH());
                    setFlagRST(analizadorTCP.flags_RST());
                    setFlagSYN(analizadorTCP.flags_SYN());
                    setFlagURG(analizadorTCP.flags_URG());
                    setWindow(analizadorTCP.window());
                    setChecksumTCP(analizadorTCP.checksum());
                    setUrgent(analizadorTCP.urgent());
                } else if(paqueteActual.hasHeader(analizadorICMP)){
                  protocolo = "ICMP";
                  setChecksumICMP(analizadorICMP.checksum());
                  setCodigoICMP(analizadorICMP.code());
                  setTipoICMP(analizadorICMP.type());
                  setDescripcionICMP(analizadorICMP.getDescription());
                  //Chequeo manual de la description de ICMP ya que el metodo a retornado null en algunas ocasiones
                  if(descripcionICMP == null){
                    if(tipoICMP == 0){
                      descripcionICMP = "echo reply";
                    }else if(tipoICMP == 3){
                      switch (codigoICMP){
                        case 0: descripcionICMP = "network unreachable"; break;
                        case 1: descripcionICMP = "host unreachable"; break;
                        case 2: descripcionICMP = "protocol unreachable"; break;
                        case 3: descripcionICMP = "port unreachable"; break;
                        case 4: descripcionICMP = "fragmentation needed, but DF bit set"; break;
                        case 5: descripcionICMP = "source route failed"; break;
                        case 6: descripcionICMP = "destination network unknown"; break;
                        case 7: descripcionICMP = "destination network unknown"; break;
                        case 9: descripcionICMP = "destination network administratevily prohibited"; break;
                        case 10: descripcionICMP = "destination host administratevily prohibited"; break;
                        case 11: descripcionICMP = "network unreachable for TOS"; break;
                        case 12: descripcionICMP = "host unreachable for TOS"; break;
                        default: descripcionICMP = "adentro afuera lento lento";
                      }
                    }else if(tipoICMP == 4){
                      descripcionICMP = "source quench";
                    }else if(tipoICMP == 5){
                      switch (codigoICMP){
                        case 0:descripcionICMP = "redirect for network"; break;
                        case 1:descripcionICMP = "redirect for host"; break;
                        case 2:descripcionICMP = "redirect for TOS and network"; break;
                        case 3:descripcionICMP = "redirect for TOS and host"; break;
                      }
                    }else if(tipoICMP == 8){
                      descripcionICMP = "echo request";
                    }else if(tipoICMP == 11){
                      if(codigoICMP == 0){
                        descripcionICMP = "time exceeded during transit";
                      }else{
                        descripcionICMP = "time exceeded during assembly";
                      }
                    }else if(tipoICMP == 12){
                      if(codigoICMP == 0){
                        descripcionICMP = "IP header bad";
                      }else{
                        descripcionICMP = "required option missed";
                      }
                    }else if(tipoICMP == 13){
                      descripcionICMP = "timestamp request";
                    }else if(tipoICMP == 14){
                      descripcionICMP = "timestamp reply";
                    }else if(tipoICMP == 17){
                      descripcionICMP = "address mask request";
                    }else {
                      descripcionICMP = "address mask reply";
                    }
                  }//null - description
                }
            }

        } else if (paqueteActual.hasHeader(analizadorIP6)) {
            //Análisis IPv6
            protocolo = "Ipv6";
        } else if (paqueteActual.hasHeader(analizadorICMP)) {
            //agregar codigo para el analisis aqui
            protocolo = "ICMP";
        } else if (paqueteActual.hasHeader(analizadorARP)) {
            //agregar codigo para el analisis aqui
            protocolo = "ARP";
        }
    }

    /*El que nos paso Axel*/
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

    //Analisis del protocolo IGMP
    private void AnalizarIGMP(){
        int indiceIGMP = ((paqueteActual.getHeader(analizadorIP4).hlen()*32)/8)+14;
        byte [] paquete = paqueteActual.getByteArray(indiceIGMP,8);
        tipoIGMPbyte=paquete[0];
        //Analizando el tipo
        if (paquete[0] == 17) {
            tipoIGMP = "Consulta";
        } else if (paquete[0] == 18) {
            tipoIGMP = "Reporte(IGMPv1)";
        } else if (paquete[0] == 22) {
            tipoIGMP = "Reporte(IGMPv2)";
        } else if (paquete[0] == 34) {
            tipoIGMP = "Reporte(IGMPv3)";
        }
        tiempoRespuesta = (paquete[1]);
        checksumIGMP = String.format("%02X", paquete[2]) + " " + String.format("%02X", paquete[3]);

        grupo = "";
        for (int i = 4; i < 8; i++) {
            grupo += paquete[i];
            if (i != 7) {
                grupo += ".";
            }
        }
        System.out.println("IGMP");
    }
    //Metodo para analisis ICMP
    private void analizarICMP(){

    }

    /*Metodos Auxiliares*/
    //Retorna un String con la fecha y tiempo de captura del paquete
    private String obtenerFecha() {
        String tiempo;
        DateFormat df = new SimpleDateFormat("MM/dd/yyyy HH:mm:ss");
        Date fecha = new Date(paqueteActual.getCaptureHeader().timestampInMillis());
        tiempo = df.format(fecha);
        return tiempo;
    }

    //Asigna la direcciones ipOrigen e ipDestino del paquete
    private void calcularIp() {
        StringBuilder aux_src = new StringBuilder();
        StringBuilder aux_dest = new StringBuilder();

        analizadorIP4 = new Ip4();
        if (!paqueteActual.hasHeader(analizadorIP4)) {
            if (paqueteActual.hasHeader(analizadorIP6)) {
                ipOrigen = asString(analizadorIP6.source());
                ipDestino = asString(analizadorIP6.destination());
            } else {
                ipOrigen = "-----";
                ipDestino = "-----";
            }
        } else {
            ipOrigen = darFormatoIPv4(analizadorIP4.source());
            ipDestino = darFormatoIPv4(analizadorIP4.destination());
        }
    }

    private String darFormatoIPv4(final byte[] mac) {
        final StringBuilder buf = new StringBuilder();
        for (byte b : mac) {
            if (buf.length() != 0) {
                buf.append('.');
            }
            buf.append((b < 0) ? b + 256 : b);
        }
        return buf.toString();
    }

    private void accederHexadecimal() {
        infoHexadecimal = paqueteActual.getByteArray(0, (paqueteActual.size()));
    }

    /*Getters y Setters*/
    public PcapPacket getPaqueteActual() {
        return paqueteActual;
    }

    public void setPaqueteActual(PcapPacket paqueteActual) {
        this.paqueteActual = paqueteActual;
    }

    public void setNumero(int numero) {
        this.numero = numero;
    }

    public void setIpOrigen(String ipOrigen) {
        this.ipOrigen = ipOrigen;
    }

    public void setIpDestino(String ipDestino) {
        this.ipDestino = ipDestino;
    }

    public void setProtocolo(String protocolo) {
        this.protocolo = protocolo;
    }

    public void setTamaño(int tamaño) {
        this.tamaño = tamaño;
    }

    public void setInfo(String info) {
        this.info = info;
    }

    public int getNumero() {
        return numero;
    }

    public String getIpOrigen() {
        return ipOrigen;
    }

    public String getIpDestino() {
        return ipDestino;
    }

    public String getProtocolo() {
        return protocolo;
    }

    public int getTamaño() {
        return tamaño;
    }

    public String getInfo() {
        return info;
    }

    public void setTiempo(String tiempo) {
        this.tiempo = tiempo;
    }

    public String getTiempo() {
        return tiempo;
    }

    public byte[] getInfoHexadecimal() {
        return infoHexadecimal;
    }

    public void setInfoHexadecimal(byte[] infoHexadecimal) {
        this.infoHexadecimal = infoHexadecimal;
    }

    public Tcp getAnalizadorTCP() {
        return analizadorTCP;
    }

    public void setAnalizadorTCP(Tcp analizadorTCP) {
        this.analizadorTCP = analizadorTCP;
    }

    public int getVersion() {
        return version;
    }

    public void setVersion(int version) {
        this.version = version;
    }

    public int getHeaderLength() {
        return headerLength;
    }

    public void setHeaderLength(int headerLength) {
        this.headerLength = headerLength;
    }

    public int getTos() {
        return tos;
    }

    public void setTos(int tos) {
        this.tos = tos;
    }

    public int getLength() {
        return length;
    }

    public void setLength(int length) {
        this.length = length;
    }

    public int getId() {
        return Id;
    }

    public void setId(int id) {
        Id = id;
    }

    public int getFlags() {
        return flags;
    }

    public void setFlags(int flags) {
        this.flags = flags;
    }

    public int getOffset() {
        return offset;
    }

    public void setOffset(int offset) {
        this.offset = offset;
    }

    public int getTtl() {
        return ttl;
    }

    public void setTtl(int ttl) {
        this.ttl = ttl;
    }

    public int getProtocoloId() {
        return protocoloId;
    }

    public void setProtocoloId(int protocoloId) {
        this.protocoloId = protocoloId;
    }

    public int getChecksum() {
        return checksum;
    }

    public void setChecksum(int checksum) {
        this.checksum = checksum;
    }

    public int getTosECN() {
        return tosECN;
    }

    public void setTosECN(int tosDesc) {
        this.tosECN = tosDesc;
    }

    public int getSrcPort() {
        return srcPort;
    }

    public void setSrcPort(int srcPort) {
        this.srcPort = srcPort;
    }

    public int getDestPort() {
        return destPort;
    }

    public void setDestPort(int destPort) {
        this.destPort = destPort;
    }

    public int getLengthUDP() {
        return lengthUDP;
    }

    public void setLengthUDP(int lengthUDP) {
        this.lengthUDP = lengthUDP;
    }

    public int getChecksumUDP() {
        return checksumUDP;
    }

    public void setChecksumUDP(int checksumUDP) {
        this.checksumUDP = checksumUDP;
    }

    public long getSeq() {
        return seq;
    }

    public void setSeq(long seq) {
        this.seq = seq;
    }

    public long getAck() {
        return ack;
    }

    public void setAck(long ack) {
        this.ack = ack;
    }

    public int getHlenTCP() {
        return hlenTCP;
    }

    public void setHlenTCP(int hlenTCP) {
        this.hlenTCP = hlenTCP;
    }

    public int getFlagsTCP() {
        return flagsTCP;
    }

    public void setFlagsTCP(int flagsTCP) {
        this.flagsTCP = flagsTCP;
    }

    public boolean getFlagCWR() {
        return flagCWR;
    }

    public void setFlagCWR(boolean flagCWR) {
        this.flagCWR = flagCWR;
    }

    public boolean getFlagECE() {
        return flagECE;
    }

    public void setFlagECE(boolean flagECE) {
        this.flagECE = flagECE;
    }

    public boolean getFlagURG() {
        return flagURG;
    }

    public void setFlagURG(boolean flagURG) {
        this.flagURG = flagURG;
    }

    public boolean getFlagACK() {
        return flagACK;
    }

    public void setFlagACK(boolean flagACK) {
        this.flagACK = flagACK;
    }

    public boolean getFlagPSH() {
        return flagPSH;
    }

    public void setFlagPSH(boolean flagPSH) {
        this.flagPSH = flagPSH;
    }

    public boolean getFlagRST() {
        return flagRST;
    }

    public void setFlagRST(boolean flagRST) {
        this.flagRST = flagRST;
    }

    public boolean getFlagSYN() {
        return flagSYN;
    }

    public void setFlagSYN(boolean flagSYN) {
        this.flagSYN = flagSYN;
    }

    public boolean getFlagFIN() {
        return flagFIN;
    }

    public void setFlagFIN(boolean flagFIN) {
        this.flagFIN = flagFIN;
    }

    public int getWindow() {
        return window;
    }

    public void setWindow(int window) {
        this.window = window;
    }

    public int getChecksumTCP() {
        return checksumTCP;
    }

    public void setChecksumTCP(int checksumTCP) {
        this.checksumTCP = checksumTCP;
    }

    public int getUrgent() {
        return urgent;
    }

    public void setUrgent(int urgent) {
        this.urgent = urgent;
    }

    public String getTipoIGMP() {
        return tipoIGMP;
    }

    public void setTipoIGMP(String tipoIGMP) {
        this.tipoIGMP = tipoIGMP;
    }

    public byte getTiempoRespuesta() {
        return tiempoRespuesta;
    }

    public void setTiempoRespuesta(byte tiempoRespuesta) {
        this.tiempoRespuesta = tiempoRespuesta;
    }

    public String getGrupo() {
        return grupo;
    }

    public void setGrupo(String grupo) {
        this.grupo = grupo;
    }

    public String getChecksumIGMP() {
        return checksumIGMP;
    }

    public void setChecksumIGMP(String checksumIGMP) {
        this.checksumIGMP = checksumIGMP;
    }

    public int getTosCode() {
        return tosCode;
    }

    public void setTosCode(int tosCode) {
        this.tosCode = tosCode;
    }

    public int getFlagReserved() {
        return flagReserved;
    }

    public void setFlagReserved(int flagReserved) {
        this.flagReserved = flagReserved;
    }

    public int getFlagDF() {
        return flagDF;
    }

    public void setFlagDF(int flagDF) {
        this.flagDF = flagDF;
    }

    public int getFlagMF() {
        return flagMF;
    }

    public void setFlagMF(int flagMF) {
        this.flagMF = flagMF;
    }

    public String getFlagDFDesc() {
        return flagDFDesc;
    }

    public void setFlagDFDesc(String flagDFDesc) {
        this.flagDFDesc = flagDFDesc;
    }

    public String getFlagMFDesc() {
        return flagMFDesc;
    }

    public void setFlagMFDesc(String flagMFDesc) {
        this.flagMFDesc = flagMFDesc;
    }

    public byte getTipoIGMPbyte() {
        return tipoIGMPbyte;
    }

    public void setTipoIGMPbyte(byte tipoIGMPbyte) {
        this.tipoIGMPbyte = tipoIGMPbyte;
    }

  public int getTipoICMP() {
    return tipoICMP;
  }

  public void setTipoICMP(int tipoICMP) {
    this.tipoICMP = tipoICMP;
  }

  public int getCodigoICMP() {
    return codigoICMP;
  }

  public void setCodigoICMP(int codigoICMP) {
    this.codigoICMP = codigoICMP;
  }

  public String getDescripcionICMP() {
    return descripcionICMP;
  }

  public void setDescripcionICMP(String descripcionICMP) {
    this.descripcionICMP = descripcionICMP;
  }

  public int getChecksumICMP() {
    return checksumICMP;
  }

  public void setChecksumICMP(int checksumICMP) {
    this.checksumICMP = checksumICMP;
  }
}
