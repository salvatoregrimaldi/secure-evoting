package servers;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import javax.net.ssl.SSLSocket;
import utility.Credential;
import utility.ElGamalCT;
import utility.ElGamalEnc;
import utility.ElGamalPK;
import utility.Schnorr;
import utility.SchnorrSig;
import utility.SignedVote;
import utility.TLSClientBidi;
import utility.Utils;

/**
 *
 * @author Nakamoteam
 */
public class Voter {

    /**
     * @brief Metodo che permette di ottenere un ID personale dopo aver
     * verificato la correttezza del certificato digitale
     * @param socket Socket su cui è stata avviata la connessione
     * @param out Stream di output della connessione
     * @param in Stream di input della connessione
     * @throws java.io.IOException
     * @throws java.lang.ClassNotFoundException
     */
    private static String sendCDForID(SSLSocket socket, ObjectOutputStream out, ObjectInputStream in) throws IOException, ClassNotFoundException, Exception {
        System.out.println("I want an ID");
        out.writeUTF("registration"); // IL VOTER INVIA UNA RICHIESTA PER FARE LA REGISTRAZIONE
        out.flush();
        // Il voter aspetta il responso di Splat
        if (in.readBoolean() == false) { // non possono essere create delle credenziali perché c'è qualcosa che non va
            System.out.println("CD check ERROR");
            return null;
        }

        // il votante si mette in attesa di ricevere il codice che gli spetta
        String ID = in.readUTF(); // il voter legge il codice inviato da Splat
        System.out.println("Arriving ID SUCCESS");
        out.writeInt(1); // Il voter risponde con un ack (= 1)
        out.flush();

        return ID;
    }

    /**
     * @brief Metodo che permette di associare all'ID una Password
     * @param ID ID univoco del Voter
     * @param pwd Password scelta dal Voter e che viene associata all'ID
     * @param socket Socket su cui è stata avviata la connessione
     * @param out Stream di output della connessione
     * @param in Stream di input della connessione
     * @throws java.io.IOException
     */
    private static Credential sendCredential(String ID, String pwd, SSLSocket socket, ObjectOutputStream out, ObjectInputStream in) throws IOException, Exception {
       // questo metodo prende in input l'ID, la password, la socket e gli stream (l'occorrente per la connessione in atto)
        
        if ("".equals(pwd)) { // la password non deve essere vuota
            System.out.println("Password empty ERROR");
            return null;
        }

        Credential cred = new Credential(ID, pwd); // creazione di un oggetto Credential, formato da ID e password
        out.writeObject(cred); // invio dell'oggetto Credential verso Splat
        out.flush();

        if (in.readBoolean() == false) { // entriamo qui se l'ID che il votante ha inviato non è esattamente quello che ha appena ricevuto
            System.out.println("Credential check ERROR");
            return null;
        }

        if (in.readBoolean() == false) { // entriamo qui se le credenziali non sono state inserite correttamente nel databse di Splat
            System.out.println("Credential not added ERROR");
            return null;
        }

        return cred;
    }

    /**
     * @brief Metodo che permette di votare
     * @param cred ID e Password del Voter
     * @param vote Preferenza espressa dal Voter
     * @param numVoter numero del Voter (necessario per l'esecuzione)
     * @throws java.io.IOException
     * @throws java.lang.ClassNotFoundException
     */
    
    // si osservi che una persona può votare anche in un momento diverso rispetto a quando ha ricevuto l'ID ed ha settato la password
    private static boolean vote(Credential cred, String vote, int numVoter) throws IOException, ClassNotFoundException, Exception {
        // questo metodo prende in input le credenziali del votante, il voto che intende fare, un numero che identifica il votante (mere ragioni implementative)
        // Il numero del votante serve all'interno del metodo per inviare il certificato corretto ad Splat
        
        // il voto deve essere per forza 0, 1, -1 o null
        // Precisazione rispetto al WP2: null è il nostro stratagemma per annullare il voto
        if (!"0".equals(vote) && !"1".equals(vote) && !"-1".equals(vote) && !"null".equals(vote)) {
            System.out.println("Vote incorrect ERROR"); // voto non valido perché diverso da {0, 1, -1, null}
            return false;
        }

        // avvio della connessione tra Votante (che fa da client) ed Splat (che fa da server)
        TLSClientBidi votToPlat = new TLSClientBidi("localhost", 50010, ".\\certificates\\voter" + numVoter + ".jks", "voter" + numVoter); // concatenazione del numero del votante per inviare il certificato corretto
        ObjectOutputStream out = new ObjectOutputStream(votToPlat.getcSock().getOutputStream());
        ObjectInputStream in = new ObjectInputStream(votToPlat.getcSock().getInputStream());

        System.out.println("I want to vote");
        out.writeUTF("voting"); // Il votante dice ad Splat che intende votare inviandogli la stringa "voting"
        out.flush();

        out.writeObject(cred); // il votante invia le credenziali
        out.flush();

        if (in.readBoolean() == false) { // io votante non ho inserito credenziali corrette
            System.out.println("Credential check ERROR");
            out.close();
            in.close();
            votToPlat.getcSock().close(); // chiusura della connessione
            return false;
        }

        // il votante si pone in attesa della chiave pubblica PK di El Gamal per cifrare.
        // Si osservi che ogni volta che un votante deve votare, Splat gli invia la PK per cifrare il voto,
        // anche se il votante vota più volte (ogni volta Splat gli manda la PK)
        ElGamalEnc PKEnc = new ElGamalEnc((ElGamalPK) in.readObject()); // il votante riceve la PK
        out.writeInt(1); // il votante invia un ACK ad Splat per indicare di aver ricevuto correttamente la PK
        out.flush();
        Schnorr signer = new Schnorr(512); // il votante crea un'istanza di Schnorr, che poi serve per firmare il ciphertext del voto

        ElGamalCT voteCT = null; // oggetto destinato a contenere il ciphertext del voto
        SchnorrSig sign = null; // oggetto destinato a contenere la firma del ciphertext
        
        // caso in cui il voto è diverso da null
        if (!"null".equals(vote)) { 
            // cifratura del voto
            voteCT = PKEnc.encryptInTheExponent(BigInteger.valueOf(Integer.parseInt(vote))); // si usa il metodo encryptInTheExponent() perché usiamo la variazione di El Gamal
            // firma con Schnorr del voto appena cifrato
            sign = signer.sign(Utils.toString(Utils.objToByteArray(voteCT)));
        }

        // se il voto espresso è uguale a null, anche gli oggetti voteCT e sign vengono lasciati a null
        out.writeObject(new SignedVote(voteCT, sign, signer.getPK())); // invio di voto cifrato, firma e PK del votante, sottoforma di oggetto SignedVote, ad Splat
        out.flush();

        if (in.readBoolean() == false) { // arriva un False da Splat
            if (voteCT == null && sign == null) {
                System.out.println("No previous vote ERROR"); // il Votante vota null come suo primo voto, e non va bene
            } else {
                System.out.println("Digital signature of vote check ERROR"); // c'è stato un problema sulla firma del voto cifrato
            }
            System.out.println("Vote ERROR"); // viene segnalato un errore di voto
            out.close();
            in.close();
            votToPlat.getcSock().close(); // chiusura della connessione
            return false;
        }
        
        // caso in cui arriva True da Splat
        System.out.println("Vote SUCCESS");

        out.close();
        in.close();
        votToPlat.getcSock().close(); // chiusura della connessione

        return true;
    }

    /**
     * @brief Voter consiste nell'insieme dei votanti e delle loro azioni
     * @param args the command line arguments
     * @throws java.lang.ClassNotFoundException
     */
    public static void main(String[] args) throws ClassNotFoundException, Exception {
        
        // setting delle proprietà del Voter
        // Si osservi che un Voter contiene solo il trust store, non ha il key store.
        // Un voter ha comunque un certificato e lo utilizza per collegarsi direttamente tramite TLS
        System.setProperty("javax.net.ssl.trustStore", ".\\certificates\\truststoreVoters.jks");
        System.setProperty("javax.net.ssl.trustStorePassword", "voters");
        
        // ATTENZIONE: IL MAIN DELLA CLASSE Voter CONTIENE TANTE ISTANZE DI VOTANTI.
        // IN PRATICA, DIRETTAMENTE NEL MAIN CI SONO TUTTE LE ISTANZE DEI VOTANTI.
        // L'OBIETTIVO è INSCENARE UNA PROVA CON DIVERSI VOTER CHE FANNO QUALCOSA DI PLAUSIBILE
        
        
        
        

        // Voter 1 vota e modifica
        TLSClientBidi votToPlat = new TLSClientBidi("localhost", 50010, ".\\certificates\\voter1.jks", "voter1");
        // Il votante fa da client: intende collegarsi con Splat, la cui porta è 50.010
        // Splat fa semplicemente una accept, ma è necessario che il voter vi si colleghi presentando il proprio certificato.
        // Si osservi che quando un server fa una acceptAndCheck, è il server che va direttamente a verificare alcuni campi del certificato del client.
        // Nel caso di una accept, invece, è importante che il client si presenti con il proprio keystore e che questo si trovi nel trust store del server.7
        // Il certificato del votante dopo servirà anche per fare il check sul suo codice fiscale.
        ObjectOutputStream out = new ObjectOutputStream(votToPlat.getcSock().getOutputStream());
        ObjectInputStream in = new ObjectInputStream(votToPlat.getcSock().getInputStream());

        // Viene richiamato il metodo sendCDForID: lo scopo è inviare il certificato digitale per ricevere un identificatore.
        // Si osservi che sendCDForID() prende in input la socket della connessione appena stabiliti e gli stream di input e di output
        String ID1 = sendCDForID(votToPlat.getcSock(), out, in);
        // Al voter è giunto un ID da Splat
        Credential cred1 = null;
        if (ID1 != null) { 
            String pwd1 = "pwdv1"; // se l'ID arrivato è diverso da null (check aggiuntivo non rilevante), allora il Voter imposta una password
            cred1 = sendCredential(ID1, pwd1, votToPlat.getcSock(), out, in); // inoltre il voter chiama il metodo sendCredential()
        }
        out.close();
        in.close();
        votToPlat.getcSock().close(); // Il votante si è registrato con successo. Chiusura della connessione

        if (cred1 != null) { // check sulle credenziali del votante (non è necessario veramente)
            vote(cred1, "-1", 1); // viene chiamato il metodo vote(), che apre una nuova connessione con Splat
            vote(cred1, "1", 1);
        }

        
        
        
        
        
        
        
        
        // Voter 2 usa ID di Voter 1 poi il suo e vota
        votToPlat = new TLSClientBidi("localhost", 50010, ".\\certificates\\voter2.jks", "voter2");
        out = new ObjectOutputStream(votToPlat.getcSock().getOutputStream());
        in = new ObjectInputStream(votToPlat.getcSock().getInputStream());

        String ID2 = sendCDForID(votToPlat.getcSock(), out, in);
        Credential cred2 = null;
        if (ID2 != null) {
            String pwd2 = "pwdv2";
            cred2 = sendCredential(ID1, pwd2, votToPlat.getcSock(), out, in); // Il votante 2 prova a loggarsi usando ID1, che è l'ID del votante 1
        }
        out.close();
        in.close();
        votToPlat.getcSock().close();

        votToPlat = new TLSClientBidi("localhost", 50010, ".\\certificates\\voter2.jks", "voter2");
        out = new ObjectOutputStream(votToPlat.getcSock().getOutputStream());
        in = new ObjectInputStream(votToPlat.getcSock().getInputStream());

        ID2 = sendCDForID(votToPlat.getcSock(), out, in);
        cred2 = null;
        if (ID2 != null) {
            String pwd2 = "pwdv2";
            cred2 = sendCredential(ID2, pwd2, votToPlat.getcSock(), out, in); // Il votante 2 stavolta si logga con id (e password) corretti
        }
        out.close();
        in.close();
        votToPlat.getcSock().close();

        if (cred2 != null) {
            vote(cred2, "1", 2);
        }

        
        
        
        
        
        
        // Voter 3 accede correttamente in piattaforma con il proprio ID, vota 0, annulla il voto, vota -1
        votToPlat = new TLSClientBidi("localhost", 50010, ".\\certificates\\voter3.jks", "voter3");
        out = new ObjectOutputStream(votToPlat.getcSock().getOutputStream());
        in = new ObjectInputStream(votToPlat.getcSock().getInputStream());

        String ID3 = sendCDForID(votToPlat.getcSock(), out, in);
        Credential cred3 = null;
        if (ID3 != null) {
            String pwd3 = "pwdv3";
            cred3 = sendCredential(ID3, pwd3, votToPlat.getcSock(), out, in);
        }
        out.close();
        in.close();
        votToPlat.getcSock().close();

        if (cred3 != null) {
            vote(cred3, "0", 3);
            vote(cred3, "null", 3);
            vote(cred3, "-1", 3);
        }

        
        
        
        
        
        
        
        
        // Voter 4 vota annulla senza aver mai votato, quindi va in contro ad un NO PREVIOUS VOTE ERROR
        votToPlat = new TLSClientBidi("localhost", 50010, ".\\certificates\\voter4.jks", "voter4");
        out = new ObjectOutputStream(votToPlat.getcSock().getOutputStream());
        in = new ObjectInputStream(votToPlat.getcSock().getInputStream());

        String ID4 = sendCDForID(votToPlat.getcSock(), out, in);
        Credential cred4 = null;
        if (ID4 != null) {
            String pwd4 = "pwdv4";
            cred4 = sendCredential(ID4, pwd4, votToPlat.getcSock(), out, in);
        }
        out.close();
        in.close();
        votToPlat.getcSock().close();

        if (cred4 != null) {
            vote(cred4, "null", 4);
        }

        
        
        
        
        
        
        
        
        // Voter 5 tenta di accedere, ma non ha i requisiti richiesti
        votToPlat = new TLSClientBidi("localhost", 50010, ".\\certificates\\voter5.jks", "voter5");
        out = new ObjectOutputStream(votToPlat.getcSock().getOutputStream());
        in = new ObjectInputStream(votToPlat.getcSock().getInputStream());

        String ID5 = sendCDForID(votToPlat.getcSock(), out, in);

        out.close();
        in.close();
        votToPlat.getcSock().close();








        // Voter 1 tenta di ottenere nuove credenziali, ma ce le ha già quindi gli vengono negate
        votToPlat = new TLSClientBidi("localhost", 50010, ".\\certificates\\voter1.jks", "voter1");
        out = new ObjectOutputStream(votToPlat.getcSock().getOutputStream());
        in = new ObjectInputStream(votToPlat.getcSock().getInputStream());

        ID1 = sendCDForID(votToPlat.getcSock(), out, in);

        out.close();
        in.close();
        votToPlat.getcSock().close();
    }

}
