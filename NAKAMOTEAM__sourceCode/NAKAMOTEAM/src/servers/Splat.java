package servers;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import static java.lang.Math.abs;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.util.encoders.Hex;
import utility.Credential;
import utility.ElGamalPK;
import utility.Schnorr;
import utility.SignedVote;
import utility.TLSClientBidi;
import utility.TLSServerBidi;
import utility.Utils;
import utility.VotesDB;

/**
 *
 * @author Nakamoteam
 */
public class Splat {

    // quelli sotto riportati sono i numeri di porta degli Sbal
    private static final int[] ports = {50000, 50001, 50002};

    private static final HashMap<String, Integer> databaseMI;

    static { // database fornito dal Ministero degli Interni che contiene i CF dei votanti.
        databaseMI = new HashMap<>(); // è una semplice hashmap che contiene CF (come chiave) e campo check come valore
        databaseMI.put("EMDM00V001", 0);
        databaseMI.put("ACXX99V002", 0);
        databaseMI.put("ADGX99V003", 0);
        databaseMI.put("SGXX99V004", 0);
    }

    /**
     * @return Codice fiscale del Voter o null
     * @brief Metodo che permette di verificare la correttezza del certificato
     * digitale
     * @param session Sessione della connessione
     * @throws javax.net.ssl.SSLPeerUnverifiedException
     */
    public static String cdVerify(SSLSession session) throws SSLPeerUnverifiedException {
        // La cdVerify prende in input la sessione di comunicazione, ovvero la connessione
        
        // getPeerPrincipal returns info about the X500Principal of the other peer
        // X500Principal è il campo "Soggetto" del certificato digitale.
        // Tale campo contiene quanto ci interessa del certificato digitale del votante
        X500Principal id = (X500Principal) session.getPeerPrincipal();
        // X500Principal is the field that contains CF, Common Name and Country
        // Il campo X500Principal contiene codice fiscale, common name e country separati da virgola

        String[] strings = id.getName().split(","); // prendiamo effettivamente la stringa associata al campo X500Principal e la splittiamo usando la virgola come separatore
        String CF = null;

        // il codice fiscale è sempre la prima voce del campo che contiene CF, Common Name and Country
        // il campo del codice fiscale DEVE SEMPRE INIZIARE CON LA STRINGA "1.3.18.0.2.6.73" perché è quella che abbiamo usato per inserire
        // il codice fiscale in un certificato. Abbiamo visto su Internet che per mettere dei campi aggiuntivi in un certificato digitale 
        // occorre usare dei codici ben specifici. Su Internet abbiamo anche visto che "1.3.18.0.2.6.73" è il codice che serve per aggiungere il CF.
        // Di default, infatti, un certificato digitale non dispone della voce CF
        if (strings[0].startsWith("1.3.18.0.2.6.73")) {  
            CF = new String(Hex.decode(strings[0].substring(21))); // prendiamo l'effettivo CF 
            // La stringa è esadecimale, quindi serve farne una decodifica, poi ne prendiamo un
            // pezzo a partire dall'indice da cui inizia il CF
        }

        if (databaseMI.containsKey(CF)) { // si va a vedere se il CF è nel databse del Ministero
            if (databaseMI.get(CF) == 0) {
                System.out.println("CD admitted SUCCESS"); // Se il CF è nel DB e il campo check è 0 (il votante non ha ancora ricevuto le credenziali), allora queste possono essere emesse
            } else {
                System.out.println("Credential already emitted ERROR"); // CF presente nel DB ma il check è a 1 --> non devono essere emesse altre credenziali
            }
        } else {
            System.out.println("Voter not admitted ERROR"); // CF non presente nel DB
        }

        if (databaseMI.containsKey(CF) && databaseMI.get(CF) == 0) {
            return CF; // se si fa il return del CF --> il voter può registrarsi
        }
        return null; // le credenziali non possono essere erogate perché o il cittadino ha già ricevuto le credenziali oppure non è un votante
    }

    /**
     * @brief Metodo che permette di inviare il voto a Sbal
     * @param ID ID univoco del Voter
     * @param oldSV voto già presente nel database espresso dal Voter
     * @param newSV nuovo voto espresso dal Voter
     * @throws java.io.IOException
     */
    public static Boolean sendToBal(String ID, SignedVote oldSV, SignedVote newSV) throws IOException, Exception {
        
        // se è tutto false (sia il nuovo voto sia il vecchio) ritorna direttamente false, perché significa che qualcosa non va
        if (oldSV.getVoteCT() == null && oldSV.getSign() == null && newSV.getVoteCT() == null && newSV.getSign() == null) {
            return false;
        }

        // determinazione del Sbal a cui inviare il voto.
        // Si prende l'ID, se ne fa l'hashcode e si fa modulo il numero di Sbal
        // Per sicurezza si fa anche il valore assoluto di quanto viene tornato (per essere sicuri che bal sia 0, 1 o 2)
        // infatti la funzione hashcode può tornare anche un numero negativo. 
        // Si osservi che è fondamentale che il voto di una certa persona vada sempre nello stesso Sbal.
        // Ad ogni ID corrisponde sempre lo stesso Sbal (fondamentale per modificare/annullare voto precedente di una certa persona)
        int bal = abs(ID.hashCode() % ports.length);

        // stampe di controllo
        System.out.println("bal: " + bal);
        System.out.println("port: " + ports[bal]);

        // avvio della connessione tra Splat e il Sbal corretto
        // Splat fa da client, mentre Sbal fa da server
        TLSClientBidi platToBal = new TLSClientBidi("localhost", ports[bal], ".\\certificates\\keystorePlat.jks", "serplat");
        ObjectOutputStream out = new ObjectOutputStream(platToBal.getcSock().getOutputStream());
        ObjectInputStream in = new ObjectInputStream(platToBal.getcSock().getInputStream());

        // Splat dice ad Sbal che intende inviare un voto
        out.writeUTF("voting");
        out.flush();

        if (in.readInt() != 1) { // ricezione di un Nack
            System.out.println("Sending string voting ERROR"); // c'è stato un errore nell'invio del SignedVote
        }
        System.out.println("Sending string voting SUCCESS");
        
        
        out.writeObject(newSV); // invio del nuovo SignedVote del votante
        out.flush();
        if (in.readBoolean() == false) { // c'è un problema con la firma del ciphertext del voto
            System.out.println("Digital signature of vote check ERROR");
            out.close();
            in.close();
            platToBal.getcSock().close();
            return false;
        }
        // nel caso in cui il voto precedente sia diverso da null, è necessario inviare anch'esso ad Sbal.
        // Infatti Sbal dovrà trovare tala coppia ciphertext-firma nel suo database e sostituirla con il nuovo voto e la sua firma
        if (oldSV.getVoteCT() != null && oldSV.getSign() != null) {
            out.writeUTF("two messages"); // Splat dichiara ad Sbal che sta per inviare anche il vecchio voto
            out.flush();

            out.writeObject(oldSV); // invio del vecchio voto
            out.flush();

            if (in.readBoolean() == false) {
                System.out.println("Digital signature of vote check ERROR");
                out.close();
                in.close();
                platToBal.getcSock().close();
                return false;
            }
        }

        // Dato che il vecchio voto era Null, ovvero il votante in questione non aveva mai votato
        // (o il suo ultimo voto è stato un annullamento) basta che Splat invii solo il nuovo SignedVote
        out.writeUTF("one message"); 
        out.flush();

        if (in.readBoolean() == false) { // il voto non è stato aggiunto in Sbal
            System.out.println("Vote not added in Sbal " + bal + "ERROR");
            out.close();
            in.close();
            platToBal.getcSock().close();
            return false;
        }

        System.out.println("Vote added in Sbal " + bal + " SUCCESS"); // voto correttamente aggiunto in Sbal
        return true;
    }






    /**
     * @brief Splat si occupa di far registrare e di far votare i Voters e di
     * inviare i voti ai Sbal
     * @param args the command line arguments
     * @throws java.io.IOException
     * @throws java.lang.ClassNotFoundException
     * @throws java.security.NoSuchAlgorithmException
     */
    public static void main(String[] args) throws IOException, ClassNotFoundException, NoSuchAlgorithmException, Exception {
        
        // setting del keystore e del truststore, con tanto di password
        System.setProperty("javax.net.ssl.keyStore", ".\\certificates\\keystorePlat.jks");
        System.setProperty("javax.net.ssl.keyStorePassword", "serplat");
        System.setProperty("javax.net.ssl.trustStore", ".\\certificates\\truststorePlat.jks");
        System.setProperty("javax.net.ssl.trustStorePassword", "serplat");

        // LA PRIMA COSA CHE DEVE FARE SPLAT è CONNETTERSI AD SGEN PER OTTENERE LA PK DI CIFRATURA DEI VOTI
        // Connessione con Sgen per ricevere la PK. Splat fa da server
        TLSServerBidi platFromSomeone = new TLSServerBidi(50010); // 50.010 è la porta alla quale Splat accetta connessioni
        SSLSocket socket = platFromSomeone.acceptAndCheckClient("CN=sgen,OU=CEN,L=Campania"); // Splat accetta la connessione da Sgen

        // Vengono creati i due outputstream per la connessione
        ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
        ObjectInputStream in = new ObjectInputStream(socket.getInputStream());

        // Splat riceve la PK per cifrare i voti da Sgen
        ElGamalPK PK = (ElGamalPK) in.readObject();
        out.writeInt(1); // Splat invia ad Sgen un riscontro del fatto di aver ricevuto la PK: Questo 1 rappresenta un feedback del ricevitore.. una sorta di ack che abbiamo implementato noi
        out.flush();
        System.out.println("Arriving PK SUCCESS");

        // Viene chiusa la connessione tra Splat ed Sgen
        out.close();
        in.close();
        socket.close();

        // INIZIO DELLA FASE DI VOTO
        // I votanti si connettono con Splat
        // Un votante può richiedere la registrazione oppure può richiedere di votare
        // Si osservi che nell'implementazione, per semplicità, dato che viene lanciata un'unica istanza di Splat,
        // può essere gestito un solo votante alla volta.
        
        // Connessione con Voter per ottenere credenziali
        VotesDB platDB = new VotesDB(); // creazione di un'istanza di "database" con campi ID, pwd hashata, salt, ciphertext, firma

        // QUELLO CHE SEGUE è UN WHILE INFINITO.
        // All'interno di tale while è presente un "break OUTER", il quale, per via dell'etichetta OUTER fa sì che il while
        // dal quale si esce sia proprio quello più esterno (tipicamente invece un break fa uscire dal ciclo più interno)
        // IN PRATICA break OUTER determina l'uscita dal while(true) e la terminazione del programma.
        
        OUTER: // etichetta associata al break outer di qualche riga più giù
        while (true) {
            socket = platFromSomeone.accept(); // accept direttamente (e non acceptAndCheckClient) perché potrebbe arrivare una richesta da uno qualsiasi dei votanti
            // stream per la comunicazione
            out = new ObjectOutputStream(socket.getOutputStream());
            in = new ObjectInputStream(socket.getInputStream());
            
            String request = in.readUTF(); // Splat legge una stringa che gli arriva dal votante
            // A cosa serve la variabile request?
            // Quando qualcuno si collega ad Splat deve "dichiarare" per quale motivo lo sta facendo.
            // Tale dichiarazione va proprio nella stringa request
            if (null != request) {
                // se request è diverso da null si procede con uno switch case.
                // Ci sono tre casi gestiti con lo switch case seguente:
                // (1) richiesta di registrazione di un votante,
                // (2) richiesta di votazione di un votante,
                // (3) richiesta di stop dal server Timer 
                switch (request) {
                    case "registration":
                        System.out.println("I received a request for an ID");
                        // Grazie a TLS, Splat ha ricevuto il certificato del votante che ha richiesto la registrazione
                        // quindi può richiamare direttamente un metodo che si occupa di fare una verifica del certificato,
                        // ovvero verifica che il codice fiscale si trovi in un certo database
                        String CF = cdVerify(socket.getSession());
                        if (CF == null) { // le credenziali non devono essere erogate
                            System.out.println("CD check ERROR");
                            out.writeBoolean(false); // Splat invia un "false" al votante per fargli capire che qualcosa non va e si chiude la connessione
                            out.flush();
                            out.close();
                            in.close();
                            socket.close();
                        } else { // è tutto apposto e le credenziali possono essere erogate
                            System.out.println("CD check SUCCESS");
                            out.writeBoolean(true);  // Splat invia un "true" al votante per fargli capire che è tutto okay
                            out.flush();
                            String ID = null;

                            do {
                                ID = Utils.generateID(); // si veda in Utils: si è utilizzato una libreria esterna, che si chiama passay
                            } while (platDB.getVotesDB().containsKey(ID)); // controllo per essere sicuro che non è stato generato un id uguale ad un altro precedentemente creato

                            out.writeUTF(ID); // Trovato un ID univoco, è possibile inviarlo al voter
                            out.flush();

                            if (in.readInt() == 1) { // se il voter invia 1, allora significa che il Votante ha correttamente ricevuto il suo id
                                System.out.println("Sending ID SUCCESS");

                                // Splat ora si mette in attesa di una password dal Voter, in particolare si aspetta di leggere un oggetto di tipo Credential
                                Credential cred = (Credential) in.readObject(); // un oggetto di tipo Credential contiene ID e password

                                // Splat riceve le credenziali impostate
                                if (!ID.equals(cred.getID())) { // l'ID deve essere esattamente uguale a quello che Splat ha appena impostato per il votante
                                    System.out.println("Credential check ERROR");
                                    out.writeBoolean(false); // invio False al Votante
                                    out.flush();
                                    out.close();
                                    in.close();
                                    socket.close(); // chiusura della connessione. Il programma non termina perché ci sono altri votanti dopo
                                } else {
                                    System.out.println("Credential check SUCCESS");
                                    out.writeBoolean(true); // Invio True al votante
                                    out.flush();

                                    // chiamata a metodo per aggiungere credenziali nel database
                                    if (platDB.addCredential(cred) == false) { // problema nell'inserimento delle credenziali nel database di Splat
                                        System.out.println("Adding credential ERROR");
                                        out.writeBoolean(false); // invio False al voter
                                        out.flush();
                                        out.close();
                                        in.close();
                                        socket.close(); // chiusura connessione
                                    } else {
                                        System.out.println("Adding credential SUCCESS"); // credenziali correttamente aggiunte al databse di Splat
                                        out.writeBoolean(true); //invio True al voter
                                        out.flush();
                                        // viene impostato a 1 il campo check associato al codice fiscale del votante
                                        databaseMI.put(CF, 1); //assumiamo funzioni sempre (non vengono fatti ulteriori controlli)
                                    }
                                }
                            } else { // il votante non ha ricevuto l'ID
                                System.out.println("Sending ID ERROR");
                                out.close();
                                in.close();
                                socket.close(); // chiusura della connessione
                            }
                        }
                        break;
                    case "voting":
                        Credential cred = (Credential) in.readObject(); // Splat riceve le credenziali dal votante
                        if (platDB.checkCredential(cred) == false) { // checkCredential() è un metodo che controlla ID e password inseriti dal votante
                            System.out.println("Credential check ERROR"); // problemi con le credenziali
                            out.writeBoolean(false); // Splat invia false al votante
                            out.flush();
                            out.close();
                            in.close();
                            socket.close(); // chiusura della connessione
                        } else {
                            System.out.println("Credential check SUCCESS"); // le credenziali sono okay
                            out.writeBoolean(true); // Splat invia True al votante
                            out.flush();

                            out.writeObject(PK); // Splat invia la PK di El Gamal per cifrare il voto (si noti che questa PK è quella ottenuta dall'aggregazione dei pezzi di PK presenti nelle share) 
                            out.flush();
                            if (in.readInt() == 1) { // ricezione dell'ACK proveniente dal votante
                                System.out.println("Sending PK SUCCESS");

                                SignedVote sv = (SignedVote) in.readObject(); // Splat riceve il pacchetto del voto dal Voter (istanza di SignedVote)
                                SignedVote oldSV = null; // SignedVote che serve per gestire il caso in cui il votante abbia già votato

                                // se sia il ciphertext del voto sia la firma del ciphertext del voto sono diversi da null, 
                                // allora significa che il votante ha effettivamente votato qualcosa
                                if (sv.getVoteCT() != null && sv.getSign() != null) {
                                    // si effettua la verify sulla firma del ciphertext
                                    if (!Schnorr.verify(sv.getSign(), sv.getSignedPK(), Utils.toString(Utils.objToByteArray(sv.getVoteCT())))) {
                                        System.out.println("Digital signature of vote check ERROR"); // problema sulla firma digitale
                                        out.writeBoolean(false); // invio di False al Votante
                                        out.flush();
                                        out.close();
                                        in.close();
                                        socket.close(); // chiusura della connessione 
                                    } else {
                                        // se arriviamo qui il voto espresso è diverso da null ed è firmato correttamente
                                        System.out.println("Digital signature of vote check SUCCESS"); // è tutto okay con la firma del ciphertext
                                        
                                        oldSV = platDB.getSignedVote(cred.getID(), sv.getSignedPK()); // Splat va a prendere l'eventuale vecchio voto del Votante presente nel database (in corrispondenza delle credenziali del votante)
                                        
                                        if (sendToBal(cred.getID(), oldSV, sv)) { // viene chiamato il metodo SendToBal
                                            // Se il nuovo voto viene aggiunto nel database di Sbal, allora viene aggiunto anche nel database di Splat
                                            // Questa cosa è importante perché i server effettivamente deputati al conteggio sono gli Sbal, non Splat
                                            platDB.setSignedVote(cred.getID(), sv); 
                                            System.out.println("Adding vote SUCCESS"); // voto correttamente aggiunto nel database di Splat
                                            out.writeBoolean(true); // Splat invia True al voter
                                            out.flush();
                                        } else {
                                            System.out.println("Adding vote ERROR"); // voto non aggiunto al database di Splat
                                            out.writeBoolean(false); // Splat invia False al voter
                                            out.flush();
                                        }
                                    }
                                } else {
                                    // il voto inviato è null, quindi non serve fare la verify
                                    oldSV = platDB.getSignedVote(cred.getID(), sv.getSignedPK()); // Splat va a prendere l'eventuale vecchio voto del Votante presente nel database (in corrispondenza delle credenziali del votante)
                                    if (sendToBal(cred.getID(), oldSV, sv)) { // inserimento del voto in Sbal
                                        platDB.setSignedVote(cred.getID(), sv); // inserimento del voto anche in Splat
                                        System.out.println("Adding vote SUCCESS");
                                        out.writeBoolean(true); // Splat invia true al voter
                                        out.flush();
                                    } else { // voto non aggiunto in Sbal
                                        System.out.println("Adding vote ERROR");
                                        out.writeBoolean(false); // Splat invia false al voter
                                        out.flush();
                                    }
                                }
                            } else { // il votante non ha ricevuto la PK
                                System.out.println("Sending PK ERROR");
                            }
                        }
                        break;
                    case "stop":
                        out.writeInt(1); // richiesta di stop arrivata (inviata dal server Timer)
                        out.flush();
                        System.out.println("e-ballot ended");
                        out.close();
                        in.close();
                        socket.close();
                        break OUTER;    // non è necessario accettare più richieste, si può uscire dal while infinito e terminare il programma
                    default:
                        System.out.println("Request not accepted ERROR");
                }
            }
        }
    }

}
