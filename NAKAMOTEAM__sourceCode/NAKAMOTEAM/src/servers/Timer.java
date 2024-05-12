package servers;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import javax.net.ssl.SSLSocket;
import utility.TLSClientBidi;
import utility.TLSServerBidi;

/**
 *
 * @author Nakamoteam
 */
public class Timer {

     // quelli sotto riportati sono i numeri di porta rispettivamente di Sgen e degli Sbal
    private static final int[] ports = {50010, 50000, 50001, 50002};

    /**
     * @brief Timer si occupa di scandire il tempo di durata della finestra
     * temporale [T1-T2] e far stoppare tutti i server al termine
     * @param args the command line arguments
     * @throws java.io.IOException
     * @throws java.lang.InterruptedException
     */
    public static void main(String[] args) throws IOException, InterruptedException, Exception {
        
        // come per tutti gli altri server, è necessario impostare keystore e truststore
        System.setProperty("javax.net.ssl.keyStore", ".\\certificates\\keystoreTim.jks");
        System.setProperty("javax.net.ssl.keyStorePassword", "sertim");
        System.setProperty("javax.net.ssl.trustStore", ".\\certificates\\truststoreTim.jks");
        System.setProperty("javax.net.ssl.trustStorePassword", "sertim");

        // Connessione con Sgen per avviare la finestra temporale [T1-T2] delle votazioni
        TLSServerBidi timFromGen = new TLSServerBidi(50021); // La porta su cui il server Timer attende la connessione è 50.021
        SSLSocket socket = timFromGen.acceptAndCheckClient("CN=sgen,OU=CEN,L=Campania"); // Il server timer accetta solo una connessione proveniente da Sgen
        socket.close(); 
        // Non appena arriva la connessione, il server Timer sa che può partire. Non gli serve sapere altro,
        // quindi può chiudere la connessione con Sgen
        // Si osservi che per la connessione appena chiusa non sono stati necessari gli stream di input e di output
        
        
        // La finestra temporale [T1-T2] nel nostro esempio dura 60 secondi
        // Il server Timer si mette in sleep per 60 secondi
        System.out.println("Sleep start");
        Thread.sleep(60000);
        System.out.println("Sleep end");
        // Il server timer finisce di dormire

        // Connessione con tutti i server necessari (tutti gli Sbal ed Splat) per inviare lo stop.
        // Si osservi che il primo server che deve essere stoppato è Splat.
        // Infatti se Splat viene fermato, sicuramente agli Sbal non arriverà più nulla.
        // Se invece Sbal si ferma mentre Splat no, può succedere che ad Splat arrivi la richiesta di un voto,
        // questo provi a contattare Sbal, questo è fuori uso --> viene lanciata un'eccezione
        for (int i = 0; i < ports.length; i++) {  
            TLSClientBidi timerToSomeone = new TLSClientBidi("localhost", ports[i], ".\\certificates\\keystoreTim.jks", "sertim");
            ObjectOutputStream out = new ObjectOutputStream(timerToSomeone.getcSock().getOutputStream());
            ObjectInputStream in = new ObjectInputStream(timerToSomeone.getcSock().getInputStream());

            out.writeUTF("stop"); // richiesta di stop
            out.flush();
            if (in.readInt() == 1) { // ack arrivato
                System.out.println("Stopping SUCCESS");
            } else { // nack arrivato
                System.out.println("Stopping ERROR");
            }

            out.close();
            in.close();
            timerToSomeone.getcSock().close(); // chiusura connessione
        }
    }
}
