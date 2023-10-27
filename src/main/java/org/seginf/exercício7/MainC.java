package org.seginf.exercício7;

import java.io.FileInputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;


public class MainC {

    public static PublicKey getPublicKeyFromCertificate(String certificateFilePath) throws Exception {
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        FileInputStream certFile = new FileInputStream(certificateFilePath);
        X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(certFile);
        return certificate.getPublicKey();
    }

    public static PrivateKey getPrivateKeyFromKeystore(String keystoreFilePath, String keystorePassword, String alias)
            throws Exception {
        KeyStore keystore = KeyStore.getInstance("JKS");
        FileInputStream keystoreFile = new FileInputStream(keystoreFilePath);
        keystore.load(keystoreFile, keystorePassword.toCharArray());

        Key key = keystore.getKey(alias, keystorePassword.toCharArray());
        if (key instanceof PrivateKey) {
            return (PrivateKey) key;
        } else {
            throw new Exception("A chave não é uma chave privada ou a senha está incorreta.");
        }
    }

    public static void main(String[] args) throws Exception {
        String certificateFilePath = "src/main/java/org/seginf/exercício7/end-entities/Alice_1.cer";
        String keystoreFilePath = "src/main/java/org/seginf/exercício7/pfx/Alice_1.pfx";

        String keystorePassword = "changeit";
        String alias = "1";

        PublicKey publicKey = getPublicKeyFromCertificate(certificateFilePath);
        System.out.println("Chave pública do certificado: " + publicKey);

        PrivateKey privateKey = getPrivateKeyFromKeystore(keystoreFilePath, keystorePassword, alias);
        System.out.println("Chave privada do keystore: " + privateKey);
    }
}
