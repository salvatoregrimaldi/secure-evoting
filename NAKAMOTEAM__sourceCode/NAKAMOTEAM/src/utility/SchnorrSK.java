package utility;

import java.math.BigInteger;

/**
 *
 * @author Nakamoteam
 */
public class SchnorrSK {

    BigInteger s;
    SchnorrPK PK;

    public SchnorrSK(BigInteger s, SchnorrPK PK) {
        this.s = s;
        this.PK = PK;

    }
}
