import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import javax.swing.JOptionPane;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapAddr;
import org.jnetpcap.PcapIf;
import org.jnetpcap.PcapSockAddr;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/**
 *
 * @author tevod
 */
public class arpform extends javax.swing.JFrame {

    String ip;
    ArrayList <String> lstIp;
    ArrayList <String> lstMac;
    public arpform() {
        lstIp = new ArrayList<>();
        lstMac = new ArrayList<>();
        initComponents();
        setLocationRelativeTo(this);

        interfaces();

        this.setDefaultCloseOperation(DISPOSE_ON_CLOSE);
    }

    private String asString(final byte[] mac)
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

    public void interfaces()
    {
        lstInterfaces.removeAllItems();
        List<PcapIf> alldevs = new ArrayList<PcapIf>(); // Will be filled with NICs
         StringBuilder errbuf = new StringBuilder(); // For any error msgs
        String ip_interfaz="";
        int r = Pcap.findAllDevs(alldevs, errbuf);
		if (r == Pcap.NOT_OK || alldevs.isEmpty()) {
			System.err.printf("Can't read list of devices, error is %s", errbuf
			    .toString());
			return;
		}

		System.out.println("Dispositivos encontrados:");
		int i = 0;
                try{
		for (PcapIf device : alldevs) {
			String description =
			    (device.getDescription() != null) ? device.getDescription()
			        : "No description available";
                        final byte[] mac = device.getHardwareAddress();
			String dir_mac = (mac==null)?"No tiene direccion MAC":asString(mac);
                        lstMac.add(dir_mac);
                        System.out.printf("\n#%d: %s [%s] MAC:[%s]\n", i++, device.getName(), description, dir_mac);
                        lstInterfaces.addItem(i++ +"  "+ description +"   "+ dir_mac);

                        Iterator<PcapAddr> it = device.getAddresses().iterator();
                        while(it.hasNext()){
                            PcapAddr dir = it.next();//dir, familia, mascara,bc
                            PcapSockAddr direccion =dir.getAddr();
                            byte[]d_ip = direccion.getData();
                            int familia=direccion.getFamily();
                            int[]ipv4 = new int[4];
                            if(familia==org.jnetpcap.PcapSockAddr.AF_INET){
                                ipv4[0]=((int)d_ip[0]<0)?((int)d_ip[0])+256:(int)d_ip[0];
                                ipv4[1]=((int)d_ip[1]<0)?((int)d_ip[1])+256:(int)d_ip[1];
                                ipv4[2]=((int)d_ip[2]<0)?((int)d_ip[2])+256:(int)d_ip[2];
                                ipv4[3]=((int)d_ip[3]<0)?((int)d_ip[3])+256:(int)d_ip[3];
                                ip="";
                                //System.out.println("\nIP4->"+ipv4[0]+"."+ipv4[1]+"."+ipv4[2]+"."+ipv4[3]);
                                for(int l=0;l<4;++l){
                                    ip+=ipv4[l]+".";
                                }
                                ip = ip.substring(0, ip.length()-1);
                                lstIp.add(ip);
                                System.out.println("\nIP4->"+ip);

                            }else if(familia==org.jnetpcap.PcapSockAddr.AF_INET6){
                                System.out.print("\nIP6-> ");
                                for(int z=0;z<d_ip.length;z++)
                                    System.out.printf("%02X:",d_ip[z]);
                            }//if
                        }//while

                        //lblIp.setText("Ip actual"+ lstIp.get(lstInterfaces.getSelectedIndex()));

		}//for
                }catch(IOException io){
                  io.printStackTrace();
                }//catch

    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jLabel1 = new javax.swing.JLabel();
        jLabel2 = new javax.swing.JLabel();
        lstInterfaces = new javax.swing.JComboBox<>();
        btnEnviar = new javax.swing.JButton();
        lblIp = new javax.swing.JLabel();
        jLabel3 = new javax.swing.JLabel();
        txtbyte1 = new javax.swing.JTextField();
        txtbyte2 = new javax.swing.JTextField();
        txtbyte3 = new javax.swing.JTextField();
        txtbyte4 = new javax.swing.JTextField();
        jLabel4 = new javax.swing.JLabel();
        jLabel5 = new javax.swing.JLabel();
        jLabel6 = new javax.swing.JLabel();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);

        jLabel1.setText("Protocolo ARP");

        jLabel2.setText("Selecciona la interface de red");

        lstInterfaces.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "Item 1", "Item 2", "Item 3", "Item 4" }));

        btnEnviar.setText("Enviar");
        btnEnviar.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnEnviarActionPerformed(evt);
            }
        });

        lblIp.setText("IP actual: ");

        jLabel3.setText("Ingresa la ip a solucionar");

        jLabel4.setText(".");

        jLabel5.setText(".");

        jLabel6.setText(".");

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                .addGap(0, 63, Short.MAX_VALUE)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                        .addComponent(lstInterfaces, javax.swing.GroupLayout.PREFERRED_SIZE, 471, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(44, 44, 44))
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                        .addComponent(btnEnviar)
                        .addGap(100, 100, 100))))
            .addGroup(layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addGap(247, 247, 247)
                        .addComponent(jLabel1))
                    .addGroup(layout.createSequentialGroup()
                        .addGap(215, 215, 215)
                        .addComponent(jLabel2))
                    .addGroup(layout.createSequentialGroup()
                        .addGap(213, 213, 213)
                        .addComponent(jLabel3))
                    .addGroup(layout.createSequentialGroup()
                        .addGap(180, 180, 180)
                        .addComponent(txtbyte1, javax.swing.GroupLayout.PREFERRED_SIZE, 41, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jLabel4, javax.swing.GroupLayout.PREFERRED_SIZE, 4, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(txtbyte2, javax.swing.GroupLayout.PREFERRED_SIZE, 40, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jLabel6, javax.swing.GroupLayout.PREFERRED_SIZE, 4, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(2, 2, 2)
                        .addComponent(txtbyte3, javax.swing.GroupLayout.PREFERRED_SIZE, 40, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jLabel5)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(txtbyte4, javax.swing.GroupLayout.PREFERRED_SIZE, 40, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addGroup(layout.createSequentialGroup()
                        .addGap(248, 248, 248)
                        .addComponent(lblIp)))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGap(35, 35, 35)
                .addComponent(jLabel1)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(jLabel2)
                .addGap(18, 18, 18)
                .addComponent(lstInterfaces, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(36, 36, 36)
                .addComponent(lblIp)
                .addGap(18, 18, 18)
                .addComponent(jLabel3)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 27, Short.MAX_VALUE)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(txtbyte1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(txtbyte2, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(txtbyte3, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(txtbyte4, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel4)
                    .addComponent(jLabel6)
                    .addComponent(jLabel5))
                .addGap(18, 18, 18)
                .addComponent(btnEnviar)
                .addGap(98, 98, 98))
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void btnEnviarActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnEnviarActionPerformed
       //validar que los campos de texto esten llenos
       String mac = lstMac.get(lstInterfaces.getSelectedIndex());
       String ipActual = lstIp.get(lstInterfaces.getSelectedIndex());
       String ipRes = txtbyte1.getText()+"."+txtbyte2.getText()+"."+txtbyte3.getText()+"."+txtbyte4.getText();

       //mandar a llamar la clase de ARP
       ARP conecta = new ARP();
       conecta.lanzaPeticion(lstInterfaces.getSelectedIndex(), ipActual, ipRes);





       //mandar datos a la clase ARP


    }//GEN-LAST:event_btnEnviarActionPerformed


    public void muestraArp(){
           try {
            for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels()) {
                if ("Nimbus".equals(info.getName())) {
                    javax.swing.UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
        } catch (ClassNotFoundException ex) {
            java.util.logging.Logger.getLogger(arpform.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(arpform.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(arpform.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(arpform.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        //</editor-fold>

        /* Create and display the form */
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                new arpform().setVisible(true);
            }
        });
    }
    /**
     * @param args the command line arguments
     */


    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton btnEnviar;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JLabel jLabel5;
    private javax.swing.JLabel jLabel6;
    private javax.swing.JLabel lblIp;
    private javax.swing.JComboBox<String> lstInterfaces;
    private javax.swing.JTextField txtbyte1;
    private javax.swing.JTextField txtbyte2;
    private javax.swing.JTextField txtbyte3;
    private javax.swing.JTextField txtbyte4;
    // End of variables declaration//GEN-END:variables
}
