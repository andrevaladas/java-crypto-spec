package com.valadas.crypto;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;

/**
 * This program demonstrates how to generate a secret-key object for
 * HMAC-MD5, and initialize an HMAC-MD5 object with it.
 */

public class initMac {

    public static void main(String[] args) throws Exception {

        // Generate secret key for HMAC-MD5
        KeyGenerator kg = KeyGenerator.getInstance("HmacMD5");
        SecretKey sk = kg.generateKey();

        // Get instance of Mac object implementing HMAC-MD5, and
        // initialize it with the above secret key
        Mac mac = Mac.getInstance("HmacMD5");
        mac.init(sk);
        byte[] result = mac.doFinal("Hi There".getBytes());
    }
}