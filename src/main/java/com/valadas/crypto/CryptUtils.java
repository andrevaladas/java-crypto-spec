package com.valadas.crypto;

import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;

/**
 * Java ™ Cryptography Architecture (JCA)
 * 
 * Some of these algorithms are described in the 
 * 	<a href="https://docs.oracle.com/javase/6/docs/technotes/guides/security/crypto/CryptoSpec.html">
 * 
 * @author André Valadas
 */
public class CryptUtils {

	/**
	 * @param args
	 * @throws Exception
	 */
	public static void main(String[] args) throws Exception {

		// testGeneratingVerifyingSignatureUsingGeneratedKeys();
		// testGeneratingVerifyingSignaturesUsingKeySpecificationsAndKeyFactory();
		//testUsingEncryption();
		// testRSAToEncryptSingleAsymmetricKey();
		// testSimpleDigitalSignatureExample();
		// testCreatesA1024BitRSAkeypairAndStoresItToTheFileSystemAsTwoFiles();
		// testRSASignatureGeneration();
		// testRSAexamplewithPKCS1Padding();
		// testEncryptDecryptWithAES_ECB_PKCS7Padding();
		testUsingPasswordBasedEncryption();
	}

	private static void testGeneratingVerifyingSignatureUsingGeneratedKeys() {

		byte[] data = "Valadas".getBytes();

		// Creating the Key Pair Generator
		KeyPairGenerator keyGen = null;
		try {
			keyGen = KeyPairGenerator.getInstance("DSA");
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		// Initializing the Key Pair Generator
		SecureRandom random;
		try {
			random = SecureRandom.getInstance("SHA1PRNG", "SUN");
			keyGen.initialize(1024, random);
		} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		// Generating the Pair of Keys
		KeyPair pair = keyGen.generateKeyPair();

		// Generating a Signature
		Signature dsa = null;
		try {
			dsa = Signature.getInstance("SHA1withDSA");
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		/* Initializing the object with a private key */
		PrivateKey priv = pair.getPrivate();
		try {
			dsa.initSign(priv);
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		/* Update and sign the data */
		try {
			dsa.update(data);
		} catch (SignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		byte[] sig = null;
		try {
			sig = dsa.sign();
		} catch (SignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		// Verifying a Signature
		/* Initializing the object with the public key */
		PublicKey pub = pair.getPublic();
		try {
			dsa.initVerify(pub);
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		/* Update and verify the data */
		try {
			dsa.update(data);
		} catch (SignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		boolean verifies = false;
		try {
			verifies = dsa.verify(sig);
		} catch (SignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		System.out.println("signature verifies: " + verifies);
	}

	public static void testGeneratingVerifyingSignaturesUsingKeySpecificationsAndKeyFactory() throws Exception {

		byte[] data = "André Valadas".getBytes();

		BigInteger x = new BigInteger("12345678", 16);
		BigInteger p = new BigInteger("12345678", 16);
		BigInteger q = new BigInteger("12345678", 16);
		BigInteger g = new BigInteger("12345678", 16);
		DSAPrivateKeySpec dsaPrivKeySpec = new DSAPrivateKeySpec(x, p, q, g);
		DSAPublicKeySpec dsaPubKeySpec = new DSAPublicKeySpec(new BigInteger("12345678", 16), new BigInteger("11", 16),
				new BigInteger("12345678", 16), new BigInteger("11", 16));

		KeyFactory keyFactory = KeyFactory.getInstance("DSA");
		PrivateKey privKey = keyFactory.generatePrivate(dsaPrivKeySpec);

		Signature sig = Signature.getInstance("SHA1withDSA");
		sig.initSign(privKey);
		sig.update(data);
		byte[] signature = sig.sign();

		PublicKey pubKeyDefault = keyFactory.generatePublic(dsaPubKeySpec);
		byte[] encodedPubKey = pubKeyDefault.getEncoded();

		X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(encodedPubKey);
		PublicKey pubKey = keyFactory.generatePublic(pubKeySpec);

		sig.initVerify(pubKey);
		sig.update(data);
		boolean verifies = sig.verify(signature);
		System.out.println("signature verifies: " + verifies);
	}

	public static void testUsingEncryption() throws Exception {
		KeyGenerator keygen = KeyGenerator.getInstance("AES");
		SecretKey aesKey = keygen.generateKey();

		// Create the cipher
		Cipher aesCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");

		// Initialize the cipher for encryption
		aesCipher.init(Cipher.ENCRYPT_MODE, aesKey);

		// Our cleartext
		byte[] cleartext = "André Valadas".getBytes();

		// Encrypt the cleartext
		byte[] ciphertext = aesCipher.doFinal(cleartext);

		// Initialize the same cipher for decryption
		aesCipher.init(Cipher.DECRYPT_MODE, aesKey);

		// Decrypt the ciphertext
		byte[] cleartext1 = aesCipher.doFinal(ciphertext);

		System.out.println(new String(cleartext));
		System.out.println(new String(cleartext1));
		// cleartext and cleartext1 are identical.
	}

	public static void testUsingPasswordBasedEncryption() throws Exception {
		PBEKeySpec pbeKeySpec;
        PBEParameterSpec pbeParamSpec;
        SecretKeyFactory keyFac;

        // Salt
        byte[] salt = {
            (byte)0xc7, (byte)0x73, (byte)0x21, (byte)0x8c,
            (byte)0x7e, (byte)0xc8, (byte)0xee, (byte)0x99
        };

        // Iteration count
        int count = 20;

        // Create PBE parameter set
        pbeParamSpec = new PBEParameterSpec(salt, count);

        // Prompt user for encryption password.
        // Collect user password as char array (using the
        // "readPassword" method from above), and convert
        // it into a SecretKey object, using a PBE key
        // factory.
        System.out.print("Enter encryption password:  ");
        System.out.flush();
        pbeKeySpec = new PBEKeySpec(ReadPassword.readPassword(System.in));
        keyFac = SecretKeyFactory.getInstance("PBEWithMD5AndDES");
        SecretKey pbeKey = keyFac.generateSecret(pbeKeySpec);

        // Create PBE Cipher
        Cipher pbeCipher = Cipher.getInstance("PBEWithMD5AndDES");

        // Initialize PBE Cipher with key and parameters
        pbeCipher.init(Cipher.ENCRYPT_MODE, pbeKey, pbeParamSpec);

        // Our cleartext
        byte[] cleartext = "André Valadas".getBytes();

        // Encrypt the cleartext
        byte[] ciphertext = pbeCipher.doFinal(cleartext);
        
        System.out.println(new String(cleartext));
		System.out.println(new String(ciphertext));
		
		// Initialize the same cipher for decryption
		System.out.print("Enter dencryption password:  ");
        System.out.flush();
		pbeKeySpec = new PBEKeySpec(ReadPassword.readPassword(System.in));
		pbeKey = keyFac.generateSecret(pbeKeySpec);
		pbeCipher.init(Cipher.DECRYPT_MODE, pbeKey, pbeParamSpec);
		
		// Decrypt the ciphertext
		byte[] cleartext1 = pbeCipher.doFinal(ciphertext);
		System.out.println(new String(cleartext1));
	}

	public static void testRSAToEncryptSingleAsymmetricKey() throws Exception {

		KeyGenerator keyGenerator = KeyGenerator.getInstance("Blowfish");
		keyGenerator.init(128);
		Key blowfishKey = keyGenerator.generateKey();

		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(1024);
		KeyPair keyPair = keyPairGenerator.genKeyPair();

		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());

		byte[] blowfishKeyBytes = blowfishKey.getEncoded();
		System.out.println(new String(blowfishKeyBytes));
		byte[] cipherText = cipher.doFinal(blowfishKeyBytes);
		System.out.println(new String(cipherText));
		cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());

		byte[] decryptedKeyBytes = cipher.doFinal(cipherText);
		System.out.println(new String(decryptedKeyBytes));
		SecretKey newBlowfishKey = new SecretKeySpec(decryptedKeyBytes, "Blowfish");
		System.out.println(newBlowfishKey);

	}

	public static void testSimpleDigitalSignatureExample() throws Exception {
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		kpg.initialize(1024);
		KeyPair keyPair = kpg.genKeyPair();

		byte[] data = "test".getBytes("UTF8");

		Signature sig = Signature.getInstance("MD5WithRSA");
		sig.initSign(keyPair.getPrivate());
		sig.update(data);
		byte[] signatureBytes = sig.sign();
		System.out.println("Singature:" + new Base64().encode(signatureBytes));

		sig.initVerify(keyPair.getPublic());
		sig.update(data);

		System.out.println(sig.verify(signatureBytes));
	}

	public static void testCreatesA1024BitRSAkeypairAndStoresItToTheFileSystemAsTwoFiles() throws Exception {

		String password = "password123";

		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(1024);
		KeyPair keyPair = keyPairGenerator.genKeyPair();
		String publicKeyFilename = "publicKey";

		byte[] publicKeyBytes = keyPair.getPublic().getEncoded();

		FileOutputStream fos = new FileOutputStream(publicKeyFilename);
		fos.write(publicKeyBytes);
		fos.close();

		String privateKeyFilename = "privateKey";

		byte[] privateKeyBytes = keyPair.getPrivate().getEncoded();

		byte[] encryptedPrivateKeyBytes = passwordEncrypt(password.toCharArray(), privateKeyBytes);

		fos = new FileOutputStream(privateKeyFilename);
		fos.write(encryptedPrivateKeyBytes);
		fos.close();
	}

	private static byte[] passwordEncrypt(char[] password, byte[] plaintext) throws Exception {
		int MD5_ITERATIONS = 1000;
		byte[] salt = new byte[8];
		SecureRandom random = new SecureRandom();
		random.nextBytes(salt);

		PBEKeySpec keySpec = new PBEKeySpec(password);
		SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBEWithMD5AndDES");
		SecretKey key = keyFactory.generateSecret(keySpec);
		PBEParameterSpec paramSpec = new PBEParameterSpec(salt, MD5_ITERATIONS);
		Cipher cipher = Cipher.getInstance("PBEWithMD5AndDES");
		cipher.init(Cipher.ENCRYPT_MODE, key, paramSpec);

		byte[] ciphertext = cipher.doFinal(plaintext);

		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		baos.write(salt);
		baos.write(ciphertext);
		return baos.toByteArray();
	}

	public static void testRSASignatureGeneration() throws Exception {
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");

		keyGen.initialize(512, new SecureRandom());

		KeyPair keyPair = keyGen.generateKeyPair();
		Signature signature = Signature.getInstance("SHA1withRSA");

		signature.initSign(keyPair.getPrivate(), new SecureRandom());

		byte[] message = "valadas".getBytes();
		signature.update(message);

		byte[] sigBytes = signature.sign();
		signature.initVerify(keyPair.getPublic());
		signature.update(message);
		System.out.println(signature.verify(sigBytes));
	}

	public static void testRSAexamplewithPKCS1Padding() throws Exception {
		byte[] input = "valadas".getBytes();
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		SecureRandom random = new SecureRandom();
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");

		generator.initialize(512, random);

		KeyPair pair = generator.generateKeyPair();
		Key pubKey = pair.getPublic();
		Key privKey = pair.getPrivate();

		cipher.init(Cipher.ENCRYPT_MODE, pubKey, random);
		byte[] cipherText = cipher.doFinal(input);
		System.out.println("cipher: " + new String(cipherText));

		cipher.init(Cipher.DECRYPT_MODE, privKey);
		byte[] plainText = cipher.doFinal(cipherText);
		System.out.println("plain : " + new String(plainText));
	}

	public static void testEncryptDecryptWithAES_ECB_PKCS7Padding() throws Exception {

		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

		byte[] input = "www.andrevaladas.com".getBytes();

		byte[] keyBytes = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,

				0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 };

		SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");

		Cipher cipher = Cipher.getInstance("AES/ECB/PKCS7Padding", "BC");

		System.out.println(new String(input));

		// encryption pass

		cipher.init(Cipher.ENCRYPT_MODE, key);

		byte[] cipherText = new byte[cipher.getOutputSize(input.length)];

		int ctLength = cipher.update(input, 0, input.length, cipherText, 0);

		ctLength += cipher.doFinal(cipherText, ctLength);

		System.out.println(new String(cipherText).getBytes("UTF-8").toString());

		System.out.println(ctLength);

		// decryption pass

		cipher.init(Cipher.DECRYPT_MODE, key);

		byte[] plainText = new byte[cipher.getOutputSize(ctLength)];

		int ptLength = cipher.update(cipherText, 0, ctLength, plainText, 0);

		ptLength += cipher.doFinal(plainText, ptLength);

		System.out.println(new String(plainText));

		System.out.println(ptLength);
	}
}
