package utility;

import java.io.Serializable;

/**
 *
 * @author Nakamoteam
 */
public class SignedVote implements Serializable {
    
    // oggetto che rappresenta il voto firmato

    private final ElGamalCT voteCT; // ciphertext del voto
    private final SchnorrSig sign; // firma del voto cifrato
    private final SchnorrPK signedPK; // PK del votante

    public SignedVote(ElGamalCT voteCT, SchnorrSig sign, SchnorrPK signedPK) {
        this.voteCT = voteCT;
        this.sign = sign;
        this.signedPK = signedPK;
    }

    public ElGamalCT getVoteCT() {
        return voteCT;
    }

    public SchnorrSig getSign() {
        return sign;
    }

    public SchnorrPK getSignedPK() {
        return signedPK;
    }
}
