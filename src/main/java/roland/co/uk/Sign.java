package roland.co.uk;


import org.bouncycastle.openssl.PEMWriter;

import java.io.FileWriter;
import java.io.IOException;
import java.io.StringWriter;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

public class Sign {
    public PrivateKey getPrivate() throws KeyStoreException, UnrecoverableEntryException, NoSuchAlgorithmException, NoSuchProviderException, IOException, CertificateException {
        KeyStore keyStore = KeyStore.getInstance("HDImageStore", "JCP");
        keyStore.load(null, null);
        char[] keyPassword = "sje2017".toCharArray();
        PrivateKey key = (PrivateKey)keyStore.getKey("Сангаджиева Юлия Эрдниевна 403105045", keyPassword);
        System.out.println(key.toString());
        return key;
    };

    public Certificate getCert() throws KeyStoreException, UnrecoverableEntryException, NoSuchAlgorithmException, NoSuchProviderException, IOException, CertificateException {
        KeyStore keyStore = KeyStore.getInstance("HDImageStore", "JCP");
        keyStore.load(null, null);
        char[] keyPassword = "sje2017".toCharArray();
        Certificate cert = (Certificate) keyStore.getCertificate("Сангаджиева Юлия Эрдниевна 403105045");
        return cert;
    };

    byte[] signed (String input) throws NoSuchProviderException, NoSuchAlgorithmException, SignatureException, KeyStoreException, UnrecoverableEntryException, InvalidKeyException, IOException, CertificateException {
        Signature sig = Signature.getInstance("GOST3411withGOST3410EL", "JCP");
        sig.initSign(getPrivate());
        sig.update(input.getBytes());
        FileWriter wr = new FileWriter("certs/san.cert");
        wr.write(toPEM(getCert()));
        wr.close();
        return  sig.sign();
    }


    byte[] dirtysigncompat(String input) throws NoSuchProviderException, NoSuchAlgorithmException, SignatureException, KeyStoreException, UnrecoverableEntryException, InvalidKeyException, IOException, CertificateException {
        Signature signer = Signature.getInstance("CryptoProSignature",                "JCP");
        signer.initSign(getPrivate());
        signer.update(input.getBytes());
        byte[] signature = signer.sign();
        return signature;
    }

    byte[] dirtysign(String input) throws NoSuchProviderException, NoSuchAlgorithmException, SignatureException, KeyStoreException, UnrecoverableEntryException, InvalidKeyException, IOException, CertificateException {
        Signature signer = Signature.getInstance("GOST3411withGOST3410EL",                "JCP");
        signer.initSign(getPrivate());
        signer.update(input.getBytes());
        byte[] signature = signer.sign();
        return signature;
    }

    public byte[] dirtysignRaw(byte[] input) throws NoSuchProviderException, NoSuchAlgorithmException, SignatureException, KeyStoreException, UnrecoverableEntryException, InvalidKeyException, IOException, CertificateException {
        Signature signer = Signature.getInstance("NONEwithGOST3410EL",                "JCP");
        signer.initSign(getPrivate());
        signer.update(input);
        byte[] signature = signer.sign();
        return signature;
    }



    byte[] signed (byte[] input) throws NoSuchProviderException, NoSuchAlgorithmException, SignatureException, KeyStoreException, UnrecoverableEntryException, InvalidKeyException, IOException, CertificateException {
        Signature sig = Signature.getInstance("GOST3411withGOST3410EL", "JCP");
        sig.initSign(getPrivate());
        sig.update(input);
        FileWriter wr = new FileWriter("certs/san.cert");
        wr.write(toPEM(getCert()));
        wr.close();
        return  sig.sign();
    }

    public String toPEM(Object obj) throws IOException {
        StringWriter out = new StringWriter();
        try (PEMWriter pem = new PEMWriter(out)) {
            pem.writeObject(obj);
        }
        return out.toString();
    }
}
