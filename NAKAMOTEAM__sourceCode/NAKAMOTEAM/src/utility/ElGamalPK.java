package utility;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.Objects;

/**
 *
 * @author Nakamoteam
 */
public class ElGamalPK implements Serializable {

    BigInteger g, h, p, q; // description of the group and public-key h=g^s
    int securityparameter; // security parameter

    public ElGamalPK(BigInteger p, BigInteger q, BigInteger g, BigInteger h, int securityparameter) {
        this.p = p;
        this.q = q;
        this.g = g;
        this.h = h;
        this.securityparameter = securityparameter;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final ElGamalPK other = (ElGamalPK) obj;
        if (this.securityparameter != other.securityparameter) {
            return false;
        }
        if (!Objects.equals(this.g, other.g)) {
            return false;
        }
        if (!Objects.equals(this.h, other.h)) {
            return false;
        }
        if (!Objects.equals(this.p, other.p)) {
            return false;
        }
        if (!Objects.equals(this.q, other.q)) {
            return false;
        }
        return true;
    }

}
