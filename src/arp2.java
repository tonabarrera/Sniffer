
import java.util.Iterator;
import java.util.List;
import org.jnetpcap.PcapAddr;
import org.jnetpcap.PcapIf;
import org.jnetpcap.PcapSockAddr;

public class arp2
{
    PcapIf device;
    byte[] MACo;
    String ipAct;
    String ipResv;
    
    public arp2(PcapIf device,String ipResv)throws Exception{
        
        this.ipResv = ipResv;
        this.device = device;
        MACo = device.getHardwareAddress();
        Iterator<PcapAddr> it = device.getAddresses().iterator();
                        while(it.hasNext()){
                            PcapAddr dir = it.next();//dir, familia, mascara,bc
                            PcapSockAddr direccion =dir.getAddr();
                            byte[]d_ip = direccion.getData();
                            int familia=direccion.getFamily();
                            int[]ipv4 = new int[4];
                            if(familia==org.jnetpcap.PcapSockAddr.AF_INET){
                                //cada entero va a ser la ip de la computadora
                                ipv4[0]=((int)d_ip[0]<0)?((int)d_ip[0])+256:(int)d_ip[0];
                                ipv4[1]=((int)d_ip[1]<0)?((int)d_ip[1])+256:(int)d_ip[1];
                                ipv4[2]=((int)d_ip[2]<0)?((int)d_ip[2])+256:(int)d_ip[2];
                                ipv4[3]=((int)d_ip[3]<0)?((int)d_ip[3])+256:(int)d_ip[3];
                                ipAct="";
                                for(int l=0;l<4;++l){
                                    ipAct+=ipv4[l]+".";
                                }
                                ipAct = ipAct.substring(0, ipAct.length()-1);
                                //System.out.println("\nIP4->"+ipAct);

                            }
                        }
        
    }
    
    
    public byte[] generaTrama(){
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
         
         return trama;
    }
    
}
