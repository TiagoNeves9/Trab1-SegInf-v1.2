package org.seginf.ex7;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;


public class jwe {

    public static String encrypt(String text, String additionalText, SecretKey symetricKey, byte[] iv, int authTagLength) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(authTagLength, iv);
        cipher.init(Cipher.ENCRYPT_MODE, symetricKey, gcmParameterSpec);

        byte[] ciphertext = cipher.doFinal(text.getBytes(StandardCharsets.UTF_8));
        String headerBase64 = Base64.getEncoder().withoutPadding().encodeToString("{\"alg\":\"RSA-OAEP-256\",\"enc\":\"A256GCM\"}".getBytes(StandardCharsets.UTF_8));
        String ciphertextBase64 = Base64.getEncoder().withoutPadding().encodeToString(ciphertext);
        String ivBase64 = Base64.getEncoder().withoutPadding().encodeToString(iv);
        String additionalTextBase64 = Base64.getEncoder().withoutPadding().encodeToString(additionalText.getBytes(StandardCharsets.UTF_8));
        // Combine os componentes em um formato JWE
        return headerBase64+ "." +ciphertextBase64+ "." +ivBase64+ "." +additionalTextBase64;
    }

    public static String decrypt(String jwe, SecretKey symetricKey, int authTagLength) throws Exception {
        String[] parts = jwe.split("\\.");
        String headerBase64 = parts[0];
        String ciphertextBase64 = parts[1];
        String ivBase64 = parts[2];
        String additionalTextBase64 = parts[3];

        byte[] iv = Base64.getDecoder().decode(ivBase64);
        byte[] ciphertext = Base64.getDecoder().decode(ciphertextBase64);
        byte[] additionalText = Base64.getDecoder().decode(additionalTextBase64);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(authTagLength, iv);
        cipher.init(Cipher.DECRYPT_MODE, symetricKey, gcmParameterSpec);

        byte[] plaintext = cipher.doFinal(ciphertext);
        //System.out.println("Texto adicional: " + new String(additionalText, StandardCharsets.UTF_8));
        return new String(plaintext, StandardCharsets.UTF_8);
    }

    //GERADOR DE CHAVES SIMETRICAS
    public static SecretKey generateAESKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256); // Tamanho da chave (AES-256)
        return keyGenerator.generateKey();
    }

    //CRIPTOGRAFAR CHAVE SIMETRICA COM CHAVE PUBLICA
    public static String encryptAESKey(SecretKey aesKey, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedKeyBytes = cipher.doFinal(aesKey.getEncoded());
        return Base64.getEncoder().withoutPadding().encodeToString(encryptedKeyBytes);
    }

    //DECRIPTOGRAFAR CHAVE SIMETRICA COM CHAVE PRIVADA
    public static SecretKey decryptAESKey(String encryptedAESKey, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] encryptedAESKeyBytes = Base64.getDecoder().decode(encryptedAESKey);
        byte[] decryptedBytes = cipher.doFinal(encryptedAESKeyBytes);
        return new SecretKeySpec(decryptedBytes, "AES");
    }

    public static PrivateKey getPrivateKeyFromKeystore(String keystoreFilePath, String keystorePassword, String alias) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("JKS");
        FileInputStream keystoreFileInput = new FileInputStream(keystoreFilePath);
        keyStore.load(keystoreFileInput, keystorePassword.toCharArray());
        keystoreFileInput.close();
        return (PrivateKey) keyStore.getKey(alias, keystorePassword.toCharArray());
    }

    public static PublicKey getPublicKeyFromCertificate(String certificateFilePath) throws Exception {
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        FileInputStream certFile = new FileInputStream(certificateFilePath);
        X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(certFile);
        certFile.close();
        return certificate.getPublicKey();
    }



    public static void main(String[] args) throws Exception {
        String certificate = args[args.length-1];
        String certificateFilePath = "end-entities/"+certificate+".cer";
        PublicKey publicKey = getPublicKeyFromCertificate(certificateFilePath);
        SecretKey encryptionKey = generateAESKey(); // Chave AES de 16 bytes (128 bits)
        String encryptedSymmetricKey = encryptAESKey(encryptionKey, publicKey); // Chave simétrica cifrada com a chave pública
        int authTagLength = 128;

        if (args[0].equals("enc")) {
            StringBuilder textToProtect = new StringBuilder();
            int i = 1;
            while (args.length - 1 > i) {
                System.out.println(args[i]);
                if(i+1 == args.length-1){
                    textToProtect.append(args[i]);
                }else {
                    textToProtect.append(args[i]).append(" ");
                }
                i++;
            }
            System.out.println("Texto a ser protegido = " + textToProtect);
            String additionalText = "Dados adicionais";
            byte[] iv = new byte[12]; // IV de 12 bytes
            new SecureRandom().nextBytes(iv);
            String jwe = encrypt(textToProtect.toString(), additionalText, encryptionKey, iv, authTagLength)+"."+encryptedSymmetricKey;
            System.out.println("JWE token = " + jwe);
        }else {
            String keystoreFilePath = "pfx/"+certificate+".pfx";
            PrivateKey privateKeyFromKeyStore = getPrivateKeyFromKeystore(keystoreFilePath, "changeit", "1");
            String jwe = args[1];
            String[] strings = jwe.split("\\.");
            SecretKey newSymmetricKey = decryptAESKey(strings[strings.length-1], privateKeyFromKeyStore); // Chave simétrica decifrada com a chave privada
            String decryptedText = decrypt(jwe, newSymmetricKey, authTagLength);
            System.out.println("Decrypted text = " + decryptedText);
        }
    }
}
