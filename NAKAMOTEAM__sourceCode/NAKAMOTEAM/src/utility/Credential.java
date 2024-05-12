package utility;

import java.io.Serializable;

/**
 *
 * @author Nakamoteam
 */
public class Credential implements Serializable {
    
    // Credential è una classe costituita banalmente da ID e password

    private final String ID;
    private final String pwd;

    public Credential(String ID, String pwd) {
        this.ID = ID;
        this.pwd = pwd;
    }

    public String getID() {
        return ID;
    }

    public String getPwd() {
        return pwd;
    }
}
