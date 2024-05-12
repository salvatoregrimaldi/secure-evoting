package utility;

import java.io.Serializable;

/**
 *
 * @author Nakamoteam
 */
public class SignedShare implements Serializable {

    private final ElGamalSK shareSK;
    private final SchnorrSig sign;
    private final SchnorrPK signedPK;

    public SignedShare(ElGamalSK shareSK, SchnorrSig sign, SchnorrPK signedPK) {
        this.shareSK = shareSK;
        this.sign = sign;
        this.signedPK = signedPK;
    }

    public ElGamalSK getShareSK() {
        return shareSK;
    }

    public SchnorrSig getSign() {
        return sign;
    }

    public SchnorrPK getSignedPK() {
        return signedPK;
    }
}
