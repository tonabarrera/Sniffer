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
  //Capa Fisica

  /*Analizando el paquete actual*/
  //Este paquete analiza un paquete de forma general, además de analizarlo de acuerdo a su
  //protocolo particular, los resultados de la analisis con guardados en sus variables correspondientes
  //para despues acceder a ellos a traves de sus getters en el frame de protocolos.
  public void analizarPaquete(){
    //Análisis de datos generales, los cuales iran en el JTable
    tiempo = obtenerFecha();
    tamaño = paqueteActual.getTotalSize();
    info = paqueteActual.getUTF8String(0,20)+"...";
    //Calculando ipOrigen e ipDestino
    calcularIp();
    //Obteniendo protocolo usado + Análisis de protocolos
    if(paqueteActual.hasHeader(analizadorIP4)){
      //Análisis del IPv4 agregar codigo para el analisis aqui
      protocolo = "Ipv4";
    }else if(paqueteActual.hasHeader(analizadorIP6)){
      //Análisis IPv6
      protocolo = "Ipv6";
    }else if(paqueteActual.hasHeader(analizadorICMP)){
      //agregar codigo para el analisis aqui
      protocolo = "ICMP";
    }else if(paqueteActual.hasHeader(analizadorARP)){
      //agregar codigo para el analisis aqui
      protocolo = "ARP";
    }else if(paqueteActual.hasHeader(analizadorTCP)){
      //agregar codigo para el analisis aqui
      protocolo = "TCP";
    }else if(paqueteActual.hasHeader((analizadorUDP))){
      //agregar codigo para el analisis aqui
      protocolo = "UDP";
    }
  }
  /*Metodos Auxiliares*/
  //Retorna un String con la fecha y tiempo de captura del paquete
  private String obtenerFecha(){
    String tiempo = "";
    DateFormat df = new SimpleDateFormat("MM/dd/yyyy HH:mm:ss");
    Date fecha = new Date(paqueteActual.getCaptureHeader().timestampInMillis());
    tiempo = df.format(fecha);
    return tiempo;
  }
  //Asigna la direcciones ipOrigen e ipDestino del paquete
  private void calcularIp(){
    byte[] sIP = new byte[4];
    byte[] dIP = new byte[4];

    analizadorIP4 = new Ip4();
    if (paqueteActual.hasHeader(analizadorIP4) == false) {
      ipOrigen = "-----";
      ipDestino = "-----";
    }else {
      sIP = analizadorIP4.source();
      dIP = analizadorIP4.destination();
      //Evitando usar el toString()
      ipOrigen = new String(sIP);
      ipDestino =  new String(dIP);
    }
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
}
