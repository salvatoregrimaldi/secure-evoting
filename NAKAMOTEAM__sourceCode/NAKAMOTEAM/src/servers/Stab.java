package servers;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.HashMap;
import javax.net.ssl.SSLSocket;
import utility.ElGamalCT;
import utility.SchnorrSig;
import utility.TLSServerBidi;

/**
 *
 * @author Nakamoteam
 */
public class Stab {

    // quelli sotto riportati sono i numeri di porta dei server Sbal
    private static final int[] ports = {50000, 50001, 50002};

    /**
     * @brief Stab si occupa di fare un merge tra tutti i database locali dei
     * Sbal e mostrarne il contenuto al termine dell'e-ballot
     * @param args the command line arguments
     * @throws java.io.IOException
     * @throws java.lang.ClassNotFoundException
     */
    public static void main(String[] args) throws IOException, ClassNotFoundException {
        
        // definizione di key store e trust store
        System.setProperty("javax.net.ssl.keyStore", ".\\certificates\\keystoreTab.jks");
        System.setProperty("javax.net.ssl.keyStorePassword", "sertab");
        System.setProperty("javax.net.ssl.trustStore", ".\\certificates\\truststoreTab.jks");
        System.setProperty("javax.net.ssl.trustStorePassword", "sertab");

        // Creazione di una Hash Map destinata a contenere coppie "cifrature di voti -- firme", con cifrature come chiavi
        HashMap<ElGamalCT, SchnorrSig> listVotes = new HashMap<>(); 

        TLSServerBidi tabFromBal = new TLSServerBidi(50020); // 50.020 è il numero di porta del server Stab

        for (int i = 0; i < ports.length; i++) {
            // accettazione delle richieste di connessione provenienti dagli Sbal
            // check del fatto che la connessione provenga da un Sbal
            SSLSocket socket = tabFromBal.acceptAndCheckClient("CN=sbal,OU=CEN,L=Campania");
            ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
            ObjectInputStream in = new ObjectInputStream(socket.getInputStream());

            // tutte le coppie "cifrature di voti -- firme" che arrivano da un Sbal vengono direttamente messe nel database listVotes
            listVotes.putAll((HashMap<ElGamalCT, SchnorrSig>) in.readObject());
            out.writeInt(1); // invio di ack al Sbal
            out.flush();
        }

        // Stampa della bacheca dei voti
        System.out.println("Table publication:\n");
        for (ElGamalCT key : listVotes.keySet()) {
            System.out.println(key + "\t" + listVotes.get(key));
        }
    }

}
