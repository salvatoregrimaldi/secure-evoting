package utility;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.HashMap;

/**
 *
 * @author Nakamoteam
 */
public class VotesDB {
    
    // Questo è il database che si trova in Splat
    // Abbiamo usato l'id come chiave; tutto il resto (hashedPwd, salt, voteCT, sign) costituisce il valore.
    // La classe è VotesDB; ValueDB è una classe innestata.
    // In pratica la classe VotesDB rappresenta una hashmap che ha come chiave gli id e come valore i valueDB

    private class ValueDB {

        private final String hashedPwd;
        private final String salt;
        private ElGamalCT voteCT;
        private SchnorrSig sign;

        public ValueDB(String hashedPwd, String salt) {
            this.hashedPwd = hashedPwd;
            this.salt = salt;
            this.voteCT = null;
            this.sign = null;
        }
    }


    private HashMap<String, ValueDB> votesDB;


    public VotesDB() {
        votesDB = new HashMap<>();
    }


    public HashMap<String, ValueDB> getVotesDB() {
        return votesDB;
    }


    public ValueDB getValueDB(String ID) {
        return votesDB.get(ID);
    }


    public boolean addCredential(Credential cred) throws NoSuchAlgorithmException {
        // Questo metodo prova ad inserire delle credenziali all'interno del database
        
        if (votesDB.containsKey(cred.getID())) { // se nel db c'è già lo stesso ID, allora non va bene e si ritorna false
            return false;
        }

        // PASSWORD HASHING
        SecureRandom sc = new SecureRandom(); 
        byte[] salt = new byte[16]; // costruzione di un salt da 16 byte
        sc.nextBytes(salt);

        MessageDigest md = MessageDigest.getInstance("SHA-256"); // viene istanziato SHA256
        md.update(salt); // aggiunta del salt
        byte[] hashedPwd = md.digest(Utils.toByteArray(cred.getPwd())); // costruzione della password hashata SHA256(salt || pwd)

        // inserimento di ID, pwd hashata e salt all'interno del DB in corrispondenza dell'ID corretto
        votesDB.put(cred.getID(), new ValueDB(Utils.toString(hashedPwd), Utils.toString(salt)));

        return true;
    }


    public boolean checkCredential(Credential cred) throws NoSuchAlgorithmException {
        // metodo usato per fare un check da parte di Splat sulle credenziali inviate dal votante
        
        ValueDB value = votesDB.get(cred.getID()); // si va a prendere il valore (pwd hashata, salt, ecc.) associato all'id

        if (value == null) { // se value è null, c'è un problema (L'ID inserito non è presente nel DB), quindi si deve ritornare false
            return false;
        }

        // CHECK DELLA PASSWORD INVIATA DALL'UTENTE
        MessageDigest md = MessageDigest.getInstance("SHA-256"); // si prende un'istanza di sha256
        md.update(Utils.toByteArray(value.salt)); // viene preso il salt
        byte[] hashedPwd = md.digest(Utils.toByteArray(cred.getPwd())); 
        
        // si calcola la password hashata e la si confronta con quella immessa dal votante
        // se la password si trova, allora viene ritornato True, altrimenti viene ritornato False
        return value.hashedPwd.equals(Utils.toString(hashedPwd));
    }


    public SignedVote getSignedVote(String ID, SchnorrPK signedPK) {
        ValueDB value = votesDB.get(ID);

        ElGamalCT voteCT = value.voteCT;
        SchnorrSig sign = value.sign;

        return new SignedVote(voteCT, sign, signedPK);
    }


    public void setSignedVote(String ID, SignedVote sv) {
        ValueDB value = votesDB.get(ID);

        value.voteCT = sv.getVoteCT();
        value.sign = sv.getSign();
    }

}
