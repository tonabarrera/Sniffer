import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.protocol.network.Arp;
import org.jnetpcap.protocol.network.Icmp;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.network.Ip6;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;

/*En esta clase se realizan las llamadas a las librerias de Jnetpcap para el análisis de un trama
* Cada instancia de esta clase recibe un paquete crudo de Pcap*/
public class AnalisisTrama {
  //Paquete a analizar
  private PcapPacket paqueteActual;
  /*Variables básicas para un paquetes, seran mostradas en la JTable de la clase Protocolos*/
  private int numero;
  
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
  /**Tona agrega aqui el ejemplo de llc por fa**/


  /*Getters y Setters*/
  public PcapPacket getPaqueteActual() {
    return paqueteActual;
  }
  public void setPaqueteActual(PcapPacket paqueteActual) {
    this.paqueteActual = paqueteActual;
  }
}
