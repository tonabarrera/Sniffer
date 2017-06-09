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
    private int length;
    private int Id;
    private int flags;
    private int offset;
    private int ttl;
    private int protocoloId;
    private int checksum;
    /*Fin de las variables IPv4*/

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
            } else {
                protocolo = "Ipv4";
                setVersion(analizadorIP4.version());
                setHeaderLength(analizadorIP4.hlen());
                setTos(analizadorIP4.tos());
                setLength(analizadorIP4.length());
                setId(analizadorIP4.id());
                setFlags(analizadorIP4.flags());
                setTtl(analizadorIP4.ttl());
                setProtocoloId(analizadorIP4.type());
                setChecksum(analizadorIP4.checksum());
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
        } else if (paqueteActual.hasHeader(analizadorTCP)) {
            //agregar codigo para el analisis aqui
            protocolo = "TCP";
        } else if (paqueteActual.hasHeader((analizadorUDP))) {
            //agregar codigo para el analisis aqui
            protocolo = "UDP";
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
        int[] sIP = new int[4];
        int[] dIP = new int[4];
        StringBuilder aux_origen = new StringBuilder();
        StringBuilder aux_destino = new StringBuilder();

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
            for (int i = 0; i < analizadorIP4.source().length; i++) {
                aux_origen.append(String.valueOf(
                        (analizadorIP4.source()[i] < 0) ? (analizadorIP4.source()[i] + 256) :
                                analizadorIP4.source()[i]));
                aux_destino.append(String.valueOf((analizadorIP4.destination()[i] < 0) ?
                        (analizadorIP4.destination()[i] + 256) : analizadorIP4.destination()[i]));
                if (i != analizadorIP4.source().length - 1) {
                    aux_origen.append(".");
                    aux_destino.append(".");
                }
            }
            //Evitando usar el toString()
            ipOrigen = aux_origen.toString();
            ipDestino = aux_destino.toString();
            //System.out.println(ipOrigen + " " + ipDestino);
        }
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
}
