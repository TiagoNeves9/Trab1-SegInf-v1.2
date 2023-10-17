package org.seginf;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/* Exemplo para gerar um valor de hash com o algorithmo SHA-256.
 * O valor de hash pode ser calculado chamando 1 vez o digest ou N vezes o update e 1 vez o digest.
 */

public class HashDemo {

    public static String calculateHash(String data) throws NoSuchAlgorithmException{
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] msg = md.digest(data.getBytes());
        StringBuilder hexString = new StringBuilder();

        for (byte hashByte : msg) {
            String hex = Integer.toHexString(0xff & hashByte);
            if (hex.length() == 1)
                hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    }

}