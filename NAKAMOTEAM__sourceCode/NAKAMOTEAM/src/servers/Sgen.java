package servers;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import utility.ElGamalGen;
import utility.ElGamalPK;
import utility.ElGamalSK;
import utility.Schnorr;
import utility.SchnorrSig;
import utility.SignedShare;
import utility.TLSClientBidi;
import utility.Utils;

/**
 *
 * @author Nakamoteam
 */
public class Sgen {

    /*
    TUTTI I SERVER HANNO ASSOCIATO PER LE COMUNICAZIONI UN NUMERO DI PORTA PERCHé TLS FUNZIONA IN QUESTO MODO.
    50.000, 50.001, 50.002 SONO I NUMERI DI PORTA DEI SERVER SBAL, MENTRE 50.010 è IL NUMERO DI PORTA DEL SERVER SPLAT.
    
    */
    private static final int[] ports = {50000, 50001, 50002, 50010}; 
    // ARRAY CONTENENTE LE PORTE DEI SERVER SBAL ED SPLAT: TRATTASI DEI SERVER CON CUI SGEN DEVE COMUNICARE

    /**
     * @brief Sgen si occupa di generare le shares di SK da distribuire ai Sbal
     * per permettere la Threashold El Gamal Decryption, la PK necessaria per
     * permettere ai Voters di votare e di avviare il Timer subito prima di
     * terminare
     * @param args the command line arguments
     * @throws java.io.IOException
     * @throws java.lang.ClassNotFoundException
     */
    
    /*NEI VARI SERVER TUTTO SI SVILUPPA NEL MAIN O IN UN'UNICA FUNZIONE (TALVOLTA VI SONO ULTERIORI FUNZIONI DI UTILITY)*/
    
    
    public static void main(String[] args) throws IOException, ClassNotFoundException {
        
        // LA PRIMA COSA DA FARE PER SETTARE UN SERVER CONSISTE NEL SETTARE LE SEGUENTI PROPRIETà,
        // CHE CONSISTONO NELL'ASSEGNAZIONE DEL CERTIFICATO E DEL TRUST STORE.
        // VENGONO SETTATE ANCHE LE PASSWORD PER KEYSTORE E TRUSTSTORE
        System.setProperty("javax.net.ssl.keyStore", ".\\certificates\\keystoreGen.jks");
        System.setProperty("javax.net.ssl.keyStorePassword", "sergen");
        System.setProperty("javax.net.ssl.trustStore", ".\\certificates\\truststoreGen.jks");
        System.setProperty("javax.net.ssl.trustStorePassword", "sergen");

        // CREIAMO ORA UN GENERATORE DI EL GAMAL.
        // 512 è IL PARAMETRO DI SICUREZZA, CIOè LA LUNGHEZZA DELLE CHIAVI
        // SI POTREBBE METTERE UN PARAMETRO MOLTO PIù ALTO: PER EL GAMAL L'IDEALE SAREBBE 2048, MA ALL'AUMENTARE DEL PARAMETRO AUMENTA
        // IL TEMPO DI ESECUZIONE, QUINDI ABBIAMO SCELTO UN PARAMETRO CHE ASSICURA UN TEMPO RAGIONEVOLE
        ElGamalGen gen = new ElGamalGen(512);

        // arrPK è UN ARRAY CHE USEREMO PER CONSERVARE LE PUBLIC KEYS ASSOCIATE ALLE VARIE SHARE.
        ElGamalPK[] arrPK = new ElGamalPK[ports.length - 1];
        // SI OSSERVI CHE L'IMPLEMENTAZIONE CHE ARRIVA TRA POCO NON FUNZIONA ESATTAMENTE COME DESCRITTO NEL WP2.
        // NEL WP2 SGEN INVIA LE SHARE DI SK AGLI SBAL E INVIA PK, COSì COM'è, AD SPLAT.
        // QUI A CAUSA DEL CODICE DI IOVINO NON POSSIAMO FARE PROPRIO COSì.
        // QUI LA PK NON è LA VERA E PROPRIA PK CHE VIENE INVIATA, MA BISOGNA FARE DELLE COSE IN PIù, ED è PER QUESTO CHE VIENE
        // UTLIZZATO L'ARRAY arrPK IN CUI SUCCESSIVAMENTE ANDREMO A METTERE DELLE PK.
        // CHE PK METTIAMO IN QUESTO ARRAY? METTIAMO LE PK ASSOCIATE ALLE SHARE INVIATE AI VARI SBAL.
        // INFATTI NELL'IMPLEMENTAZIONE DI IOVINO OGNI SHARE è UNA COPPIA (PEZZETTINO DI SK, PEZZETTINO DI PK).
        // POSSIAMO SCORDARCI LA PK CHE ABBIAMO GENERATO POCO SOPRA INSIEME AD SK... NON CI SERVIRà MAI A NIENTE PER VIA DI IOVINO.
        // ORA NOI PRENDIAMO LA SK E LA DIVIDIAMO IN TANTI PEZZETTI. CIASCUN PEZZETTO HA UNA "PROPRIA" PK.
        // QUESTI PEZZI DI PK CI SERVONO PERCHé DEVONO ESSERE UNITI (C'è UN METODO APPOSTA CHE LO FA) PER FORMARE LA PK FINALE
        
        // VIENE CREATO UN OGGETTO ISTANZA DI SCHNORR, CHE SERVE PER FIRMARE
        Schnorr signer = new Schnorr(512);

        // Connessione con tutti i Sbal per inviare le shares
        
        // SGEN INVIA UNA SHARE AD OGNI SBAL. 
        // IN TAL MODO OGNI SBAL AVRà UN PEZZETTINO DI SK ED UNA PK ASSOCIATA.
        // OGNI SBAL MANDA POI IL PROPRIO PEZZETTINO DI PK (QUELLO CHE STA DENTRO ALLA SHARE) AD SGEN.
        // SGEN RACCOGLIE TUTTI QUESTI PEZZI DI PK IN arrPK, QUINDI POI CHIAMA UN METODO, CHE SI CHIAMA aggregate.
        // QUESTO METODO FA L'AGGREGAZIONE DI QUESTI PEZZI DI PK E RESTITUISCE LA PK FINALE, CHE è QUELLA CHE SERVIRà
        // PER CIFRARE I VOTI.
        
        // IL MECCANISMO DI CONNESSIONE USATO PREVEDE CHE SIA IL CLIENT A CHIEDERE LA CONNESSIONE.
        
        // CONNESSIONI VERSO I SERVER SBAL
        for (int i = 0; i < ports.length - 1; i++) {
            TLSClientBidi genToBal = new TLSClientBidi("localhost", ports[i]); //genToBal è la connessione tra Sgen e l'i-esimo Sbal
            // la connessione viene instaurata indicando chi si vuole collegare (localhost sono io stesso Sgen) e a chi si
            // vuole collegare (Sbal i-esimo)

            // Ogni volta che si crea una connessione bisogna creare un OutputStream out ed un InputStream in, che
            // nella pratica rappresentano il canale di comunicazione.
            // Se io devo ricevere uso in, se devo inviare uso out.
            ObjectOutputStream out = new ObjectOutputStream(genToBal.getcSock().getOutputStream());
            ObjectInputStream in = new ObjectInputStream(genToBal.getcSock().getInputStream());

            ElGamalSK shareSK = gen.getPartialSecret(); // creazione di una share, sfruttando il generatore gen

            SchnorrSig sign = signer.sign(Utils.toString(Utils.objToByteArray(shareSK))); // firma della share
            // si osservi che il metodo objToByteArray si trova nel file utils e trasforma un oggetto in un array di byte, che
            // poi può essere trasformato in stringa

            // Sgen manda in output un oggetto, che è un pacchetto, istanza di SignedShare, che contiene
            // la share, la firma di Schnorr e la PK di Schnorr (associata alla SK usata per firmare).
            // Si osservi che la SK usata per firmare non è quella del certificato (per motivi implementativi sempre legati a Iovino).
            // I certificati, infatti, non usano la firma di Schnorr... che era l'unica che Iovino ci ha dato.
            // Quindi per questioni implementative abbiamo dovuto distaccarci dai certificati.
            out.writeObject(new SignedShare(shareSK, sign, signer.getPK()));
            out.flush(); // il metodo flush serve per essere sicuri che sia stato effettivamente mandato qualcosa e
            // l'abbiamo chiamato dopo ogni writeObject

            // ogni volta che c'è un in. significa che il Server sta aspettando che gli arrivi qualcosa che poi dovrà leggere.
            // Si osservi che readBoolean è bloccante. Quando il codice arriva ad un in si blocca in attesa che arrivi
            // qualcosa dall'interlocutore.
            // Ora Sgen attende una risposta da parte bell'Sbal a cui ha mandato un SignedShare.
            // La risposta di Sbal sarà False oppure True.
            
            if (in.readBoolean() == false) { // CASO FIRMA DELLA SHARE CHE NON VA BENE
                System.out.println("Digital signature of share check ERROR"); 
                out.close();
                in.close();
                genToBal.getcSock().close(); // chiusura connessione
                return; // Sgen termina. Si deve per forza fermare perché c'è un problema con la coppia di chiavi da usare poi per i voti
            }

            // controllo: il pezzo di PK in arrivo dall'Sbal seve essere esattamente uguale
            // al pezzettino di PK che Sgen ha inviato allo stesso Sbal all'interno della share.
            // Questo è un controllo in più per essere sicuri che il Sbal abbia esattamente lo stesso
            // pezzettino di Pk che è stato mandato da Sgen
            if (!shareSK.getPK().equals(in.readObject())) {
                System.out.println("PK check ERROR");
                out.writeBoolean(false);
                out.flush();
                out.close();
                in.close();
                genToBal.getcSock().close();
                return;
            }
            out.writeBoolean(true); // il pezzettino di Pk arrivato da Sbal è buono, quindi io Sgen metto in arrPK il pezzettino di PK
            out.flush();
            arrPK[i] = shareSK.getPK(); // si noti che se è tutto okay, questa cosa viene fatta con tutti e 3 gli Sbal, quindi arrPK avrà 3 elementi

            out.close();
            in.close();
            genToBal.getcSock().close(); // tutto okay, la connessione per le share si può chiudere
        }

        // Connessione con tutti i server necessari per inviare la PK
        
        //  A QUESTO PUNTO, AVENDO A DISPOSIZIONE I 3 PEZZETTI DI PK ASSOCIATI ALLE SHARE, è POSSIBILE COSTRUIRE LA SHARE VERA E PROPRIA 
        // DA USARE PER CIFRARE I VOTI. Per effettuare la costruzione della PK finale che servirà per cifrare i voti, è necessario
        // chiamare il metodo aggregatePartialPublicKeys().
        
        ElGamalPK PK = gen.aggregatePartialPublicKeys(arrPK);
        
        // Secondo il nostro WP2, la PK dovrebbe essere passata solo ad Splat, ma in realtà per
        // motivi implementativi viene passata anche agli Sbal.
        // Quali sono questi motivi implementativi? Gli Sbal faranno i conti sui ciphertext di El Gamal, quindi faranno sempre "mod p",
        // dove p è un parametro che è contenuto proprio nella PK

        // Si fa un nuovo for che serve per inviare la PK effettiva per cifrare i voti sia ad Splat sia agli Sbal
        // (anche agli Sbal per quanto detto sopra)
        for (int i = 0; i < ports.length; i++) {
            TLSClientBidi genToSomeone = new TLSClientBidi("localhost", ports[i]); // Sgen funge ancora da client

            ObjectOutputStream out = new ObjectOutputStream(genToSomeone.getcSock().getOutputStream());
            ObjectInputStream in = new ObjectInputStream(genToSomeone.getcSock().getInputStream());

            out.writeObject(PK); // invio della PK
            out.flush(); // Solita flush

            // OSSERVAZIONE: Per le verifiche abbiamo usato un booleano.
            // quando invece viene ricevuto qualcosa punto e basta (senza verifiche) viene inviato 1 o 0 (0 nel caso di mancata ricezione) 
            if (in.readInt() == 1) {
                System.out.println("Sending Key SUCCESS");
            } else {
                System.out.println("Sending Key ERROR");
            }

            out.close();
            in.close();
            genToSomeone.getcSock().close();
        }
        
        // Dopo che Sgen si assicura che Splat e gli Sbal abbiano la PK di cifratura per El Gamal
        // e che gli Sbal abbiano le share della SK di El Gamal, tecnicamente è possibile iniziare con le operazioni di voto.
        // Viene instaurata una connessione tra Sgen ed il server Timer. 
        // Tale connessione ha l'unico scopo di dire al Timer "Ora puoi partire".
        
        // Lo start del timer viene dato da Sgen perché, essendosi collegato con tutti quelli che avevano bisogno di qualcosa per
        // iniziare la procedura di voto, sa se è tutto okay per tutti.
        // Quando Sgen capisce che gli altri server (gli Sbal ed Splat) hanno tutto il necessario per iniziare
        // la procedura di voto, avvia il timer
        TLSClientBidi genToTimer = new TLSClientBidi("localhost", 50021); // 50.021 è il numero di porta associato al server Timer
        genToTimer.getcSock().close();  // Dopo essersi assicurato di avviare il Timer, Sgen può smettere di eseguire

    }

}
