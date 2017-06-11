import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.nio.ByteBuffer;  
import java.util.ArrayList;  
import java.util.Arrays;  
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;  
import javax.swing.JOptionPane;
import jdk.nashorn.internal.ir.LoopNode;
  
import org.jnetpcap.Pcap;  
import org.jnetpcap.PcapAddr;
import org.jnetpcap.PcapBpfProgram;
import org.jnetpcap.PcapIf;  
import org.jnetpcap.PcapSockAddr;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;  
public class ARP {  
    static PcapIf device;
    static StringBuilder errbuf;
    private static String asString(final byte[] mac) 
    {
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
    
  public void lanzaPeticion(int indice,String ipAct,String ipResv) {  
    List<PcapIf> alldevs = new ArrayList<PcapIf>(); // Will be filled with NICs  
    errbuf = new StringBuilder(); // For any error msgs  
    String ip_interfaz="";

    		int r = Pcap.findAllDevs(alldevs, errbuf);
		if (r == Pcap.NOT_OK || alldevs.isEmpty()) {
			System.err.printf("Can't read list of devices, error is %s", errbuf.toString());
			return;
		}

   try{
    device = alldevs.get(indice); // We know we have atleast 1 device  
       /******************************************************/
        Iterator<PcapAddr> it1 = device.getAddresses().iterator();
       /******************************************************/
       byte[] MACo = device.getHardwareAddress();
               int snaplen = (64 * 1024); // Capture all packets, no trucation  
    int flags = Pcap.MODE_PROMISCUOUS; // capture all packets  
    int timeout = 10 * 1000; // 10 seconds in millis  
    Pcap pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);  
  

          
            byte[] trama = new byte[42];
    
   trama[0] = (byte) 0xFF;
   trama[1] = (byte) 0xFF;
   trama[2] = (byte) 0xFF;
   trama[3] = (byte) 0xFF;
   trama[4] = (byte) 0xFF;
   trama[5] = (byte) 0xFF;
    for(int k=0;k<MACo.length;k++){
        trama[k+6]=MACo[k];
    }

    trama[12]= (byte) 0x08; //tipo sin asignar
    trama[13]= (byte) 0x06; //tipo ARP  usamos protocolo ARP
    
    trama[14] = (byte) 0x00;
    trama[15] = (byte) 0x01; //2 bytes para el tipo de hardware
    
    trama[16] = (byte) 0x08;
    trama[17] = (byte) 0x00; //tipo de protocolo 
    
    trama[18] = (byte) 0x06; //tamaño direccion hardware
    
    trama[19] = (byte) 0x04; //Tamaño de la direccion ip
    
    trama[20] = (byte) 0x00; //Tipo de operacion 
    trama[21] = (byte) 0x01; // 1 para request 2 para respuesta
    
   for(int k=0;k<MACo.length;k++){
        trama[k+22]=MACo[k]; // copiamos la direccion mac del origen/emisor
    }

   
   String val="";
   int j=0;
   for(int i= 0;i<ipAct.length();++i){
       if(ipAct.charAt(i)=='.'){
           trama[j+28]=(byte)Integer.parseInt(val);
           j+=1;
           val="";
       }else{
           val = val+ipAct.charAt(i);
       }
   }
   trama[31]=(byte)Integer.parseInt(val);
   
    for(int k=0;k<6;k++){
        trama[k+32]=(byte)0x00; // copiamos la direccion mac del destino, como es la primera trama seran ceros
    } 
    
    //esta es la ip destino la cachamos en ipresv
    val = "";
    j=0;
    for(int i=0;i<ipResv.length();++i){
        if(ipResv.charAt(i)=='.'){
            trama[j+38] = (byte)Integer.parseInt(val);
            j+=1;
            val="";
        }else{
            val=val+ipResv.charAt(i);
        }
        
    }
    
    trama[41] = (byte)Integer.parseInt(val);
     
    ByteBuffer b = ByteBuffer.wrap(trama);  
    
     PcapBpfProgram filter = new PcapBpfProgram();
            String expression ="ether proto 0x0800"; // "port 80";
            int optimize = 0; // 1 means true, 0 means false
            int netmask = 0;
            int r2 = pcap.compile(filter, expression, optimize, netmask);
            if (r2 != Pcap.OK) {
                System.out.println("Filter error: " + pcap.getErr());
            }//if
            pcap.setFilter(filter);
    
     if (pcap.sendPacket(trama) != Pcap.OK) {  
          System.err.println(pcap.getErr());  
            }
            System.out.println("Envié un paquete******");
        
    //cachar mi ip
     
       
    capturaPaquete();
    
    pcap.breakloop();
    
   }catch(Exception e){
       e.printStackTrace();
   }//catch
  }  
  
  public static void capturaPaquete()
  {
                  int snaplen = (64 * 1024); // Capture all packets, no trucation  
    int flags = Pcap.MODE_PROMISCUOUS; // capture all packets  
    int timeout = 10 * 1000; // 10 seconds in millis  
    Pcap pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);  
      
      
          //poner en un while infinito para cachar paquetes arp y verificar cual es nuestra respuesta :D
        PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {			
        @Override
        public void nextPacket(PcapPacket packet, String user) {

            
				
                                int tipo = (packet.getUByte(12)*256)+packet.getUByte(13);
                                
                                
                                if(tipo==2054){ //0x2048 tipo arp
                                    System.out.printf("Tipo= %d",tipo);
                                    
                                    System.out.printf("Paquete capturado el %s bytes capturados=%-4d tam original=%-4d %s\n",
				    new Date(packet.getCaptureHeader().timestampInMillis()),
				    packet.getCaptureHeader().caplen(),  // Length actually captured
				    packet.getCaptureHeader().wirelen(), // Original length
				    user                                 // User supplied object
				    );
                                    /******Desencapsulado********/
                                    System.out.println("MAC destino:");
                                    for(int i=0;i<6;i++){
                                    System.out.printf("%02X ",packet.getUByte(i));
                                    }
                                    System.out.println("");
                                    System.out.println("MAC origen:");
                                    for(int i=6;i<12;i++){
                                    System.out.printf("%02X ",packet.getUByte(i));
                                    }
                                    System.out.println("");
                                    System.out.println("Tipo:");
                                    for(int i=12;i<14;i++){
                                    System.out.printf("%02X ",packet.getUByte(i));
                                    }
                                    
                                    /*System.out.println("\n");
                                    for(int i=14;i<packet.size();++i){
                                        System.out.printf("%02X ",packet.getUByte(i));
                                    }*/
                                    System.out.println("\n");
                                    

                                   byte[]t = packet.getByteArray(0, packet.size());
                                   
                                   /*if(t[21]==2){
                                       for(int k=0;k<t.length;k++)
                                        System.out.printf("tipo = %02X \n",t[k]);
                                   }*/
                                   
                                   
                                   
                                   StringBuilder str = new StringBuilder();
                                   for(int i=22;i<28;++i){
                                       str.append(String.format("%02X ", t[i]));
                                   }
                                   
                                  
                                       
                                    System.out.println("La direccion mac es"+str.toString().substring(0, str.toString().length()-1));
                                    JOptionPane.showMessageDialog(null, "La direccion mac es:  "+str.toString().substring(0, str.toString().length()-1));
                                    pcap.breakloop();
                                  
                                   
                                    
                                   

                                }

			}
		};
    
             try{
                 Thread.sleep(500);
             }catch(InterruptedException e){}
             pcap.loop(Pcap.LOOP_INFINITE, jpacketHandler, "");
      
      
       
  }
}  
