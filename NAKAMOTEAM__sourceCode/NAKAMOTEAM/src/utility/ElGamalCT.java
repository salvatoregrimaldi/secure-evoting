package utility;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.Objects;

/**
 *
 * @author Nakamoteam
 */
public class ElGamalCT implements Serializable {

    BigInteger C, C2;

    public ElGamalCT(BigInteger C, BigInteger C2) {
        this.C = C;
        this.C2 = C2;

    }

    public ElGamalCT(ElGamalCT CT) {
        this.C = CT.C;
        this.C2 = CT.C2;

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
        final ElGamalCT other = (ElGamalCT) obj;
        if (!Objects.equals(this.C, other.C)) {
            return false;
        }
        if (!Objects.equals(this.C2, other.C2)) {
            return false;
        }
        return true;
    }

    public static ElGamalCT Homomorphism(ElGamalPK PK, ElGamalCT CT1, ElGamalCT CT2) {
        ElGamalCT CT = new ElGamalCT(CT1); // CT=CT1
        CT.C = CT.C.multiply(CT2.C).mod(PK.p);  // CT.C=CT.C*CT2.C mod p
        CT.C2 = CT.C2.multiply(CT2.C2).mod(PK.p); // CT.C2=CT.C2*CT2.C2 mod p
        return CT; // If CT1 encrypts m1 and CT2 encrypts m2 then CT encrypts m1+m2

    }

    @Override
    public String toString() {
        return "ElGamalCT{" + "C=" + C + ", C2=" + C2 + '}';
    }

}
