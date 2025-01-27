package utility;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.SecureRandom;
import static org.passay.AllowedCharacterRule.ERROR_CODE;
import org.passay.CharacterData;
import org.passay.CharacterRule;
import org.passay.EnglishCharacterData;
import org.passay.PasswordGenerator;

/**
 *
 * @author Nakamoteam
 */
public class Utils {

    private static final String digits = "0123456789abcdef";

    public static String toHex(byte[] data, int length) {
        StringBuffer buf = new StringBuffer();
        for (int i = 0; i != length; i++) {
            int v = data[i] & 0xff;
            buf.append(digits.charAt(v >> 4));
            buf.append(digits.charAt(v & 0xf));
        }
        return buf.toString();
    }

    public static String toHex(byte[] data) {
        return toHex(data, data.length);
    }

    public static String toString(byte[] bytes, int length) {
        char[] chars = new char[length];

        for (int i = 0; i != chars.length; i++) {
            chars[i] = (char) (bytes[i] & 0xff);
        }

        return new String(chars);
    }

    public static String toString(byte[] bytes, int from, int length) {
        char[] chars = new char[length];

        for (int i = from; i != chars.length; i++) {
            chars[i] = (char) (bytes[i] & 0xff);
        }

        return new String(chars);
    }

    public static String toString(byte[] bytes) {
        return toString(bytes, bytes.length);
    }

    public static byte[] toByteArray(String string) {
        byte[] bytes = new byte[string.length()];
        char[] chars = string.toCharArray();

        for (int i = 0; i != chars.length; i++) {
            bytes[i] = (byte) chars[i];
        }

        return bytes;
    }

    public static byte[] objToByteArray(Object obj) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream out = null;
        byte[] yourBytes;
        try {
            out = new ObjectOutputStream(bos);
            out.writeObject(obj);
            out.flush();
            yourBytes = bos.toByteArray();

        } finally {
            bos.close();
        }

        return yourBytes;
    }

    public static Object byteArrayToObj(byte[] bytes) throws IOException, ClassNotFoundException {
        ByteArrayInputStream bis = new ByteArrayInputStream(bytes);
        ObjectInput in = null;
        Object o = null;
        try {
            in = new ObjectInputStream(bis);
            o = in.readObject();
        } finally {

            if (in != null) {
                in.close();
            }
        }
        return o;
    }

    // creazione dell'ID utilizzando una libreria esterna che prende il nome di Passay
    public static String generateID() {
        // L'obiettivo è ottenere una stringa casuale ALFANUMERICA: sfrutta numeri, lettere, simboli speciali
        
        // Creazione di un generatore di password usando un oggetto SecureRandom per la casualità
        PasswordGenerator gen = new PasswordGenerator(new SecureRandom());
        
        // Definizione delle regole per i caratteri da includere nella password
        // Qui si definiscono quante lettere minuscole, maiuscole, cifre e simboli speciali includere

        // englishCharacterData è un'enumerazione di sets di caratteri, tra cui lettere minuscole inglesi,
        // lettere maiuscole inglesi, cifre.
        
        // Regola per le lettere minuscole
        CharacterData lowerCaseChars = EnglishCharacterData.LowerCase;
        CharacterRule lowerCaseRule = new CharacterRule(lowerCaseChars);
        lowerCaseRule.setNumberOfCharacters(2); // Includi almeno 2 lettere minuscole

        // Regola per le lettere maiuscole
        CharacterData upperCaseChars = EnglishCharacterData.UpperCase;
        CharacterRule upperCaseRule = new CharacterRule(upperCaseChars);
        upperCaseRule.setNumberOfCharacters(2); // Includi almeno 2 lettere maiuscole

        // Regola per le cifre
        CharacterData digitChars = EnglishCharacterData.Digit;
        CharacterRule digitRule = new CharacterRule(digitChars);
        digitRule.setNumberOfCharacters(2); // Includi almeno 2 cifre

        // Regola per i simboli speciali
        CharacterData specialChars = new CharacterData() {
            public String getErrorCode() {
                return ERROR_CODE;
            }

            public String getCharacters() {
                return "!@#$%^&*()_+";
            }
        };
        CharacterRule splCharRule = new CharacterRule(specialChars);
        splCharRule.setNumberOfCharacters(2); // Includi almeno 2 simboli speciali

        // Generazione di una password di lunghezza 10, contenente almeno
        // 2 lettere minuscole, 2 lettere maiuscole, 2 cifre e 2 simboli speciali,
        // creando quindi una stringa alfanumerica casuale e robusta
        String password = gen.generatePassword(10, splCharRule, lowerCaseRule, upperCaseRule, digitRule);
        return password;
    }

}
