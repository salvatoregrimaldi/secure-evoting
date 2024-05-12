package servers;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.ConnectException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Scanner;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import javax.net.ssl.SSLSocket;
import utility.ElGamalCT;
import utility.ElGamalDec;
import utility.ElGamalPK;
import utility.ElGamalSK;
import utility.Schnorr;
import utility.SchnorrSig;
import utility.SignedShare;
import utility.SignedVote;
import utility.TLSClientBidi;
import utility.TLSServerBidi;
import utility.Utils;

/**
 *
 * @author Nakamoteam
 */
public class Sbal {

    // Di seguito sono riportati i numeri di porta dei server Sbal
    private static final int[] ports = {50000, 50001, 50002};

    /**
     * @brief Metodo che permette di far eseguire tutto ciò che deve fare uno
     * Sbal
     * @param port Numero della porta dello Sbal
     * @throws java.io.IOException
     * @throws java.lang.ClassNotFoundException
     * @throws java.net.ConnectException
     */
    private static void activateSbal(int port) throws IOException, ClassNotFoundException, Exception, ConnectException {
        
        // setting delle proprietà: keystore e truststore
        System.setProperty("javax.net.ssl.keyStore", ".\\certificates\\keystoreBal.jks");
        System.setProperty("javax.net.ssl.keyStorePassword", "serbal");
        System.setProperty("javax.net.ssl.trustStore", ".\\certificates\\truststoreBal.jks");
        System.setProperty("javax.net.ssl.trustStorePassword", "serbal");
        TLSServerBidi balFromSomeone = new TLSServerBidi(port); // si noti che Bidi sta per bidirectional
        
        // Sbal funge da server, quindi si pone in attesa di qualcuno ("someone"); quindi non funge da client.
        // I client richiedono le connessioni, i server invece si pongono in attesa di connessioni.
        // balFromSomeone è un'istanza di TLSServerBidi che verrà usata per fare più connessioni

        
        
        // quando ci si deve collegare con qualcuno si possono usare due metodi forniti dalla classe TLSServerBidi:
        // - acceptAndCheck(): accetta la connessione verificando chi si sta connettendo
        // - accept(): accetta la connessione e basta
        // Sbal sa che deve collegarsi proprio con Sgen quindi si deve assicurare che la richiesta di connessione provenga da qualcuno
        // che nel certificato possiede le voci "CN=sgen,OU=CEN,L=Campania".
        // In tal modo Sbal si assicura di accettare richieste di connessione provenienti solo da Sgen.
        // Si noti che anche il metodo acceptAndCheckClient è bloccante

        // Connessione con Sgen per ricevere la share
        SSLSocket socket = balFromSomeone.acceptAndCheckClient("CN=sgen,OU=CEN,L=Campania");
        
        // creazione di out e in per la connessione
        ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
        ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
        
        // Sbal legge il SignedShare che arriva da Sgen.
        // Si osservi che quando si richiama una readObject() poi bisogna sempre fare un 
        // cast al tipo dell'oggetto che si sta leggendo.
        SignedShare share = (SignedShare) in.readObject();

        // Viene richiamata la verify su Schnorr per verificare se la firma della share è corretta
        // Si noti che i messaggi di errore/successo sono fatti tutti nel modo seguente: messaggio || ERROR/SUCCESS
        if (!Schnorr.verify(share.getSign(), share.getSignedPK(), Utils.toString(Utils.objToByteArray(share.getShareSK())))) {
            System.out.println("Digital signature of share check ERROR");
            System.out.println("--------------------          " + port);
            out.writeBoolean(false); // LA FIRMA DELLA SHARE NON è BUONA, QUINDI SBAL INVIA FALSE AD SGEN
            out.flush();
            out.close(); // CHIUSURA DELLA CONNESSIONE sempre con le istruzioni out.close(), in.close(), socket.close()
            in.close();
            socket.close();
            return; // TERMINAZIONE DEL PROGRAMMA
        }
        out.writeBoolean(true); // LA FIRMA DELLA SHARE è BUONA
        out.flush();
        System.out.println("Arriving share SUCCESS");
        System.out.println("--------------------          " + port);

        // Viene creata l'istanza di un decifratore di El Gamal con la share inviata da Sgen
        ElGamalDec shareDec = new ElGamalDec((ElGamalSK) share.getShareSK());

        // invio del pezzo di PK della share verso Sgen
        out.writeObject(shareDec.getPK());
        out.flush();

        if (in.readBoolean() == false) { // se il pezzettino di Pk che ho inviato non è buono, segnalo l'errore e chiudo la connessione.
            System.out.println("PK check ERROR");
            System.out.println("--------------------          " + port);
            out.close();
            in.close();
            socket.close();
            return;
        }

        out.close();
        in.close();
        socket.close(); // tutto okay per il momento, si può chiudere la connessione

        

        
        // Connessione con Sgen per ricevere la PK
        socket = balFromSomeone.acceptAndCheckClient("CN=sgen,OU=CEN,L=Campania"); // La connessione viene accettata solo se a richiederla è Sgen
        // così si evitano avversari/impostori che potrebbero mandare chiavi fasulle
        out = new ObjectOutputStream(socket.getOutputStream());
        in = new ObjectInputStream(socket.getInputStream());

        ElGamalPK PK = (ElGamalPK) in.readObject(); // Sbal ottiene la PK
        if (PK != null) { // Tutto apposto, la PK è arrivata --> Sbal manda 1 ad Sgen 
            out.writeInt(1);
            out.flush();
            System.out.println("Arriving PK SUCCESS");
            System.out.println("--------------------          " + port);
        } else { // La PK è null --> c'è un problema --> Sbal manda 0 ad Sgen
            out.writeInt(0);
            out.flush();
            System.out.println("Arriving PK ERROR");
            System.out.println("--------------------          " + port);

        }
        out.close();
        in.close();
        socket.close(); // Chiusura della connessione tra Sbal ed Sgen
        
        
        

        // Connessione con Splat per ricevere i voti (inizio dell'e-ballot)
        System.out.println("\nI am ready to start the e-ballot\n");
        System.out.println("--------------------          " + port);

        // Sbal dispone di un mini database interno contenente coppie di ciphertext-firma
        HashMap<ElGamalCT, SchnorrSig> listVotes = new HashMap<>();
        
        
        // ciclo infinito per gestire varie connessioni
        OUTER:
        while (true) {
            System.out.println("sono sbal e sono entrato nel while");
            System.out.println("--------------------          " + port);

            // si accetta una connessione da qualcuno
            socket = balFromSomeone.accept();
            // apertura della connessione con gli stream
            out = new ObjectOutputStream(socket.getOutputStream());
            in = new ObjectInputStream(socket.getInputStream());
            
            String request = in.readUTF(); // arrivo di una stringa che specifica cosa desidera fare chi si è connesso ad Sbal
            // ci sono due casi di richieste:
            // (1) stop: viene inviato esclusivamente dal timer
            // (2) voting: viene inviato esclusivamente da Splat
            out.writeInt(1); // invio di ACK al richiedente
            out.flush();
            
            if (null != request) { // la request deve essere diversa da null
                System.out.println("request is not null and it is: " + request);
                System.out.println("--------------------          " + port);
                switch (request) {
                    case "stop":
                        out.writeInt(1); // richiesta di stop arrivata, inviata dal server Timer
                        //out.flush();
                        out.close();
                        in.close();
                        socket.close();
                        break OUTER;
                    
                    case "voting": // Sbal riceve un SignedVote da parte di Splat
                        SignedVote sv = (SignedVote) in.readObject(); // Sbal riceve il SignedVote
                        out.writeBoolean(true); // Sbal invia True ad Splat per confermare la corretta ricezione del SignedVote
                        out.flush();
                        
                        if (sv.getVoteCT() == null && sv.getSign() == null) { // caso in cui sia il ciphertext del voto sia la sua firma sono null
                            // l'invio della stringa "two messages" da parte di Splat verso Sbal significa che in precedenza è stato
                            // espresso un voto che ora va sostituito con il nuovo
                            if ("two messages".equals(in.readUTF())) {
                                SignedVote oldSV = (SignedVote) in.readObject(); // ricezione del vecchio voto

                                out.writeBoolean(true); // Invio di True da Sbal ad Splat
                                out.flush();
                                System.out.println("Arriving vote SUCCESS");
                                System.out.println("--------------------          " + port);
                                for (ElGamalCT key : listVotes.keySet()) {
                                    if (key.equals(oldSV.getVoteCT())) { // ricerca del vecchio voto nel database contenente solo ciphertext-firma
                                        if (listVotes.remove(key, listVotes.get(key))) { // il voto vecchio niene rimosso e non se ne aggiunge nessuno perché il nuovo voto è null
                                            out.writeBoolean(true); // Sbal invia ad Splat True perché la rimozione del voto è avvenuta correttamente
                                            out.flush();
                                            System.out.println("Adding vote SUCCESS");
                                            System.out.println("--------------------          " + port);
                                        } else {
                                            out.writeBoolean(false); // il vecchio voto non è stato trovato, quindi non può essere rimosso
                                            out.flush();
                                            System.out.println("Adding vote ERROR");
                                            System.out.println("--------------------          " + port);
                                        }
                                    }
                                }
                            }
                        } else { // caso in cui il voto espresso è diverso da null
                            if (!Schnorr.verify(sv.getSign(), sv.getSignedPK(), Utils.toString(Utils.objToByteArray(sv.getVoteCT())))) { // verify della firma del voto cifrato
                                System.out.println("Digital signature of vote check ERROR"); // errore sulla verify
                                System.out.println("--------------------          " + port);
                                out.writeBoolean(false);
                                out.flush();
                            } else {
                                out.writeBoolean(true);
                                out.flush();
                                System.out.println("Arriving vote SUCCESS"); // è tutto okay con la verify
                                System.out.println("--------------------          " + port);

                                if ("two messages".equals(in.readUTF())) { // il nuovo voto inviato deve sovrascriverne uno vecchio
                                    SignedVote oldSV = (SignedVote) in.readObject(); // ricezione del vecchio SignedVote

                                    out.writeBoolean(true); // Invio di True da Sbal ad Splat
                                    out.flush();
                                    System.out.println("Arriving vote SUCCESS");
                                    System.out.println("--------------------          " + port);
                                    // ricerca del vecchio SignedVote 
                                    for (ElGamalCT key : listVotes.keySet()) {
                                        if (key.equals(oldSV.getVoteCT())) {
                                            // rimozione del vecchio SignedVote ed aggiunta del nuovo
                                            if (listVotes.remove(key, listVotes.get(key)) && sv.getVoteCT() != null && sv.getSign() != null && !listVotes.containsKey(sv.getVoteCT())) {
                                                // nell'if di sopra le condizioni che vengono dopo la remove in realtà non sono utili. Si controlla se il nuovo SignedVote sia diverso da null e se effettivamente non esista alcun vecchio SignedVote con lo stesso ciphertext nel db di Sbal
                                                listVotes.put(sv.getVoteCT(), sv.getSign());
                                                out.writeBoolean(true);
                                                out.flush();
                                                System.out.println("Adding vote SUCCESS");
                                                System.out.println("--------------------          " + port);
                                            } else {
                                                out.writeBoolean(false);
                                                out.flush();
                                                System.out.println("Adding vote ERROR");
                                                System.out.println("--------------------          " + port);
                                            }
                                        }
                                    }
                                } else { // il nuovo voto è diverso da null, lo si può aggiungere direttamente nel database di Sbal
                                    if (sv.getVoteCT() != null && sv.getSign() != null && !listVotes.containsKey(sv.getVoteCT())) {
                                        listVotes.put(sv.getVoteCT(), sv.getSign());
                                        out.writeBoolean(true);
                                        out.flush();
                                        System.out.println("Adding vote SUCCESS");
                                        System.out.println("--------------------          " + port);
                                    } else {
                                        out.writeBoolean(false);
                                        out.flush();
                                        System.out.println("Adding vote ERROR");
                                        System.out.println("--------------------          " + port);
                                    }
                                }
                            }
                        }
                        out.close();
                        in.close();
                        socket.close(); // chiusura connessione
                        break;
                    default:
                        System.out.println("Request not accepted ERROR"); // caso in cui arriva una richiesta anomala, che non sia nè "voting" né "stop"
                }
            }
        }
        System.out.println("\ne-ballot ended\n");
        System.out.println("--------------------          " + port);
        
        
        
        
        

        // Calcolo del ciphertext locale (fine dell'e-ballot).
        // Ciascun Sbal moltiplica i ciphertext dei voti che ha disposizione ed ottiene un unico ciphertext locale.
        // Ciascun Sbal invia il proprio ciphertext locale agli altri Sbal.
        // Alla fine (per ragioni implementative) solo uno degli Sbal riesce effettivamente a calcolare il ciphertext finale.
        ElGamalCT localCT = null; // variabile destinata a contenere il ciphertext locale di un Sbal
        int flag = 0;

        // Si ricordi che nel database di Sbal abbiamo unicamente coppie ciphertext-firma, con il ciphertext che fa da chiave
        for (ElGamalCT key : listVotes.keySet()) { // si itera sulle chiavi del DB di Sbal, ovvero sui ciphertext dei voti che ha a disposizione
            if (flag == 0) {
                localCT = key; // non appena in localCT viene messo il primo ciphertext, flag viene settato a 1
                flag = 1;
            } else { // per tutti gli altri ciphertext nel database si richiama il metodo Homomorphism(), che effettua la moltiplicazione del prodotto corrente con il ciphertext i-esimo
                localCT = ElGamalCT.Homomorphism(PK, localCT, key);
            }
        }

        
        // Connessione con gli altri Sbal per inviare il ciphertext locale
        ArrayList<ElGamalCT> arrCT = new ArrayList<>(); // Sbal prepara un array arrCT destinato a contenere i ciphertext locali che gli vengono inviati dagli altri Sbal
        ElGamalCT tmp = null;

        // osservazione: ports contiene le porte associate ai 3 Sbal, ovvero 50.000, 50.001, 50.002
        for (int i = 0; i < ports.length; i++) {
            // IO SBAL INVIO
            if (ports[i] != port) { // se ports[i] è diverso dalla mia porta, allora invio il mio ciphertext locale
                TLSClientBidi balToBal = new TLSClientBidi("localhost", ports[i]); // creazione connessione con l'altro Sbal
                out = new ObjectOutputStream(balToBal.getcSock().getOutputStream());
                in = new ObjectInputStream(balToBal.getcSock().getInputStream());

                out.writeObject(localCT); // invio del ciphertext locale
                out.flush();

                if (in.readInt() == 1) { // arrivo dell'ack dal Sbal a cui ho inviato il mio ciphertext locale
                    System.out.println("Sending local ciphertext SUCCESS");
                    System.out.println("--------------------          " + port);
                } else {
                    System.out.println("Sending local ciphertext ERROR"); // arriva un nack dall'Sbal a cui ho inviato il ciphertext locale --> qualcosa è andato storto
                    System.out.println("--------------------          " + port);
                }

                out.close();
                in.close();
                balToBal.getcSock().close();
            } else {
                // IO SBAL RICEVO. 
                for (int j = 0; j < ports.length - 1; j++) { // naturalmente devo ricevere dagli altri n-1 Sbal. In questo esempio n-1 = 2
                    // un altro Sbal sta provando ad inviarmi qualcosa
                    socket = balFromSomeone.acceptAndCheckClient("CN=sbal,OU=CEN,L=Campania");
                    out = new ObjectOutputStream(socket.getOutputStream());
                    in = new ObjectInputStream(socket.getInputStream());

                    tmp = (ElGamalCT) in.readObject(); // ricevo un ciphertext locale

                    out.writeInt(1); // invio ack al Sbal mittente
                    out.flush();
                    System.out.println("Arriving local ciphertext SUCCESS");
                    System.out.println("--------------------          " + port);

                    if (tmp != null) {
                        arrCT.add(tmp); // aggiunta del ciphertext locale ad arrCT.
                        // Si osservi che si è usato un ArrayList (e non un array normale) come arrCT per poter
                        // fare semplicemente add() senza dover specificare alcun indice
                    }

                    out.close();
                    in.close();
                    socket.close(); // chiusura connessione
                }
            }
        }
        
        // Giunti a questo punto, ogni Sbal dispone del proprio ciphertext locale e
        // di un array che contiene gli altri n-1 ciphertext locali che gli sono stati inviati dagli altri Sbal

        // Calcolo del ciphertext finale (fine dell'e-ballot)
        
        
        if (localCT == null & arrCT.isEmpty()) { // caso in cui nessuno ha votato
            System.out.println("Nobody voted final ciphertext is null");
            System.out.println("--------------------          " + port);
            return;
        }

        ElGamalCT finalCT = localCT;

        if (localCT == null) { // caso in cui questo Sbal non dispone di alcun voto, ovvero il suo localCT è null
            finalCT = arrCT.get(0); 
            for (int i = 1; i < arrCT.size(); i++) {
                finalCT = ElGamalCT.Homomorphism(PK, finalCT, arrCT.get(i)); // calcolo del prodotto di tutti i ciphertext locali
            }
        } else { // caso in cui questo Sbal dispone di almeno un voto
            for (int i = 0; i < arrCT.size(); i++) {
                finalCT = ElGamalCT.Homomorphism(PK, finalCT, arrCT.get(i)); // calcolo del prodotto di tutti i ciphertext locali
            }
        }

        // A questo punto ciascuno Sbal ha il finalCT, ovvero il ciphertext del risultato delle elezioni
        // Per motivi implementativi (codice messoci a disposizione da Iovino) la decifratura del ciphertext finale avviene tipo "catena di Sant'Antonio"   
        
        // Connessione con gli altri Sbal per inviare ufin^(p(i))
        ElGamalCT personalDecCT = shareDec.partialDecrypt(finalCT); // Ognuno degli Sbal calcola il proprio contributo ufin^(p(i)) per la Threshold El Gamal Decryption
        // Si osservi che il metodo partialDecrypt() va richiamato su un oggetto della classe ElGamalDec.
        // Il metodo partialDecrypt ritorna in pratica il contributo per la Threshold El Gamal Decryption, ovvero u^(p(i)).
        // Guardando la riga di codice di sopra: p(i) fa capo a shareDec, mentre u fa capo a finalCT
        
        for (int i = 0; i < ports.length - 1; i++) { // il numero di step da effettuare è n-1, dove n = # Sbal
            if (ports[i] != port) { // IO SBAL RICEVO DAGLI ALTRI 2 SBAL  
                socket = balFromSomeone.acceptAndCheckClient("CN=sbal,OU=CEN,L=Campania"); // accetto una connessione
                out = new ObjectOutputStream(socket.getOutputStream());
                in = new ObjectInputStream(socket.getInputStream());

                if (i != ports.length - 2) { // non sono all'ultimo step: il Sbal che riceve moltiplica quello che riceve per il proprio contributo
                    personalDecCT = shareDec.partialDecrypt((ElGamalCT) in.readObject()); 
                } else { // sono all'ultimo step: il Sbal che riceve non deve moltiplicare quello che riceve per qualcos'altro, ma riceve e basta
                    personalDecCT = (ElGamalCT) in.readObject();
                }

                out.writeInt(1);
                out.flush();
                System.out.println("Arriving partial decrypt SUCCESS");
                System.out.println("--------------------          " + port);

                out.close();
                in.close();
                socket.close();
            } else { // IO SBAL INVIO AGLI ALTRI 2 SBAL 
                for (int j = 0; j < ports.length; j++) {
                    if (ports[j] != port) { // Io Sbal mi assicuro di non inviare a me stesso
                        TLSClientBidi balToBal = new TLSClientBidi("localhost", ports[j]);
                        out = new ObjectOutputStream(balToBal.getcSock().getOutputStream());
                        in = new ObjectInputStream(balToBal.getcSock().getInputStream());

                        out.writeObject(personalDecCT);
                        out.flush();

                        if (in.readInt() == 1) {
                            System.out.println("Sending partial decrypt SUCCESS");
                            System.out.println("--------------------          " + port);
                        } else {
                            System.out.println("Sending partial decrypt ERROR");
                            System.out.println("--------------------          " + port);
                        }

                        out.close();
                        in.close();
                        balToBal.getcSock().close();
                    }
                }
            }
        }
        // alla fine di questo ciclo, il server Sbal con numero di porta 50.002 (in pratica l'ultimo Sbal degli n, ovvero il terzo) si ritrova con la
        // quantità u^(p(0))*u^(p(1)). Pertanto, facendo richiamare a tale server la partialDecrypt(), questa restituisce in output u^(p(0))*u^(p(1))*u^(p(2))

        // Calcolo del risultato finale dell'e-ballot
        if (port == ports[ports.length - 1]) { // Il calcolo finale viene fatto da un solo Sbal, in particolare da quello con numero di porta uguale a 50.002
            BigInteger res = shareDec.decryptInTheExponent(personalDecCT); // viene chiamato il metodo che si occupa della decifratura con Variazione di El Gamal, che fa prima una partial decrypt
            System.out.println("The e-ballot result is: " + res);
            System.out.println("--------------------          " + port);
        }

        //Connessione con la bacheca per la stampa dei voti
        TLSClientBidi balToTab = new TLSClientBidi("localhost", 50020); // ciascun Sbal si collega ad Stab e gli manda la propria lista di voti
        out = new ObjectOutputStream(balToTab.getcSock().getOutputStream());
        in = new ObjectInputStream(balToTab.getcSock().getInputStream());

        out.writeObject(listVotes); // invio delle coppie cifratura voto -- firma da Sbal ad Stab
        out.flush();

        if (in.readInt() == 1) { // invio effettuato con successo
            System.out.println("Sending DB SUCCESS");
            System.out.println("--------------------          " + port);
        } else {
            System.out.println("Sending DB ERROR"); // errore nell'invio
            System.out.println("--------------------          " + port);
        }

        out.close();
        in.close();
        balToTab.getcSock().close(); // chiusura della connessione
    }




    /**
     * @brief Sbal si occupa di ricevere i voti ed inserirli correttamente nel
     * database, di ottenere il risultato finale del ballottaggio collaborando
     * con gli altri Sbal e di inviare il database a Stab
     * @param args the command line arguments
     * @throws java.lang.InterruptedException
     * @throws java.lang.ClassNotFoundException
     */
    
    // LANCIAMO 3 ISTANZE DIVERSE DI SBAL, QUINDI FACCIAMO UN VERO E PROPRIO MULTI-THREAD.
    // OGNI THREAD (NE VENGONO CREATI 3 IN TUTTO) è UN'ISTANZA DI SBAL.
    // AD OGNI SBAL VIENE ASSOCIATO IL NUMERO DI PORTA GIUSTO (50.001, 50.002 o 50.003).
    // QUINDI BASTA RUNNARE DIRETTAMENTE UNA VOLTA SBAL PER OTTENERNE TRE ISTANZE.
    public static void main(String[] args) throws InterruptedException, ClassNotFoundException, Exception {
        List<Callable<Void>> taskList = new ArrayList<>();
        for (int i = 0; i < ports.length; i++) {
            int port = ports[i];
            Callable<Void> callable = new Callable<Void>() {
                @Override
                public Void call() throws Exception {
                    activateSbal(port); // VIENE RICHIAMATO IL METODO activateSbal, CHE CONTIENE TUTTO QUELLO CHE UNO SBAL DEVE FARE
                    // QUINDI ABBIAMO IN PARALLELO 3 SBAL CHE ESEGUONO IL PROPRIO METODO activateSbal
                    return null;
                }
            };
            taskList.add(callable);
        }
        ExecutorService executor = Executors.newFixedThreadPool(3);
        executor.invokeAll(taskList);
        executor.shutdown();
        /*
        Scanner scan = new Scanner(System.in);
        System.out.print("Enter port number: ");
        int numPort = scan.nextInt();
        activateSbal(numPort);
         */
    }

}
