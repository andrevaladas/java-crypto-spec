package com.valadas.crypto;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * This program generates a Blowfish key, retrieves its raw bytes, and then
 * reinstantiates a Blowfish key from the key bytes. The reinstantiated key is
 * used to initialize a Blowfish cipher for encryption.
 */

public class BlowfishKey {

	public static void main(String[] args) throws Exception {

		KeyGenerator kgen = KeyGenerator.getInstance("Blowfish");
		SecretKey skey = kgen.generateKey();
		byte[] raw = skey.getEncoded();
		SecretKeySpec skeySpec = new SecretKeySpec(raw, "Blowfish");

		Cipher cipher = Cipher.getInstance("Blowfish");
		cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
		byte[] encrypted = cipher.doFinal("This is just an example".getBytes());
	}
}