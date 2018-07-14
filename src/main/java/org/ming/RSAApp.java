package org.ming;


import javax.crypto.Cipher;
import java.security.*;

public class RSAApp {
    public static void main(String[] args) throws Exception {
        // generate public and private keys
        KeyPair keyPair = buildKeyPair();
        PublicKey pubKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        serverToClient(pubKey, privateKey, "Hello, This is a message");

        clientToServer(pubKey, privateKey, "Hello, This is a message");

    }

    public static void serverToClient(PublicKey pubKey, PrivateKey privateKey, String message) throws Exception {
        // encrypt the message
        byte[] encrypted = encrypt(privateKey, message);
        System.out.println(new String(encrypted));  // <<encrypted message>>

        // decrypt the message
        byte[] secret = decrypt(pubKey, encrypted);
        System.out.println(new String(secret));     // This is a secret message
    }

    public static void clientToServer(PublicKey publicKey, PrivateKey privateKey, String message) throws Exception {
        byte[] encrypted = encrypt(publicKey, message);
        System.out.println(new String(encrypted));

        byte[] secret = decrypt(privateKey, encrypted);
        System.out.println(new String(secret));


    }


    public static KeyPair buildKeyPair() throws NoSuchAlgorithmException {
        final int keySize = 2048;
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(keySize);
        return keyPairGenerator.genKeyPair();
    }

    public static byte[] encrypt(PrivateKey privateKey, String message) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);

        return cipher.doFinal(message.getBytes("UTF-8"));
    }

    public static byte[] encrypt(PublicKey publicKey, String message) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        return cipher.doFinal(message.getBytes("UTF-8"));
    }

    public static byte[] decrypt(PublicKey publicKey, byte[] encrypted) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, publicKey);

        return cipher.doFinal(encrypted);
    }


    public static byte[] decrypt(PrivateKey privateKey, byte[] encrypted) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        return cipher.doFinal(encrypted);

    }
}
