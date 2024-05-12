package utility;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.Objects;

/**
 *
 * @author Nakamoteam
 */
public class SchnorrSig implements Serializable {

    BigInteger a, e, z;

    public SchnorrSig(BigInteger a, BigInteger e, BigInteger z) {
        this.a = a;
        this.e = e;
        this.z = z;
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
        final SchnorrSig other = (SchnorrSig) obj;
        if (!Objects.equals(this.a, other.a)) {
            return false;
        }
        if (!Objects.equals(this.e, other.e)) {
            return false;
        }
        if (!Objects.equals(this.z, other.z)) {
            return false;
        }
        return true;
    }

    @Override
    public String toString() {
        return "a=" + a + ", e=" + e + ", z=" + z;
    }

}
