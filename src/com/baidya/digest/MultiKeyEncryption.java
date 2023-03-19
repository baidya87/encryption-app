package com.baidya.digest;

import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * Use Symmetric encryption to encrypt/decrypt secret message.
 * The key is itself encrypted using asymmetric encryption.
 * 
 * @author baidya
 *
 */
public class MultiKeyEncryption {

	//message to be encrypted
	private static final String SECRET = "Complete your stocks account by verifying via Aadhaar OTP and start investing in India's to companies.";
	
	/**
	 * generates the Symmetric Key
	 * @return
	 */
	public static String generateSecretKey() {
		try {
			KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
			keyGenerator.init(128);
			SecretKey secretKey = keyGenerator.generateKey();
			//System.out.println(Base64.getEncoder().encodeToString(secretKey.getEncoded()));
			return Base64.getEncoder().encodeToString(secretKey.getEncoded());
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return null;
	}
	
	/**
	 * The symmetric key itself is encrypted using asymmetric encryption.
	 * encode using PUBLIC
	 * decode using PRIVATE
	 * @return
	 */
	public static KeyPair generateKeyPair() {
		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(2048);
			return keyPairGenerator.generateKeyPair();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return null;
	}
	
	public static String getPrivateKey(KeyPair keyPair) {
		return Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());
	}
	
	public static String getPublicKey(KeyPair keyPair) {
		return Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
	}
	
	/**
	 * Encrypt secret message using Symmetric encryption 
	 * Encrypt key using the Asymmetric Public Key.
	 * @param publicKey
	 * @return
	 */
	public static SecretMessage sendSecrets(PublicKey publicKey) {
		
		String key = generateSecretKey(); // generates Secret Key encoded in Base64 string format.
		byte[] decodedKey = Base64.getDecoder().decode(key.getBytes(Charset.forName("UTF-8"))); // decode to bytes
		try {
			SecretKey secretKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES"); // recreate the secret key from decoded bytes.
			Cipher cipher = Cipher.getInstance("AES");	// cipher is set
			cipher.init(Cipher.ENCRYPT_MODE, secretKey); // to encryption mode
			byte[] encryptedSecretMessage = cipher.doFinal(SECRET.getBytes(Charset.forName("UTF-8"))); // encrypt the secret message.
			SecretMessage message = new SecretMessage();
			message.setSecretMessage(Base64.getEncoder().encodeToString(encryptedSecretMessage)); // encode to Base64 string format.

			// use the cipher to encrypt the secret key with RSA public KEY.
			cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, publicKey);
			message.setSecretKey(Base64.getEncoder().encodeToString(cipher.doFinal(secretKey.getEncoded())));
			return message;
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		}
		
		return null;
	}
	
	/**
	 * uses private key to decrypt the encrypted secret key & then uses the key to decrypt the secret message. 
	 * @param secretMessage
	 * @param privateKey
	 */
	public static void readSecret(SecretMessage secretMessage, PrivateKey privateKey) {
		System.out.println(secretMessage.getSecretMessage());
		try {
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, privateKey);
			byte[] decryptedSecretKey = cipher.doFinal(Base64.getDecoder().decode(secretMessage.getSecretKey().getBytes(Charset.forName("UTF-8"))));
			SecretKey secretKey = new SecretKeySpec(decryptedSecretKey, 0, decryptedSecretKey.length, "AES");
			
			//byte[] encryptedSecretKey = Base64.getDecoder().decode(secretMessage.getSecretKey().getBytes(Charset.forName("UTF-8")));
			//byte[] decryptedSecretKey = cipher.doFinal(encryptedSecretKey);
			//SecretKey secretKey = new SecretKeySpec(decryptedSecretKey, "AES");
			
			cipher = Cipher.getInstance("AES");
			cipher.init(Cipher.DECRYPT_MODE, secretKey);
			byte[] decryptedMessageBytes = cipher.doFinal(Base64.getDecoder().decode(secretMessage.getSecretMessage().getBytes(Charset.forName("UTF-8"))));
			System.out.println(new String(decryptedMessageBytes, Charset.forName("UTF-8")));
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		}
	}
	
	public static void main(String[] args) {
		KeyPair keyPair = generateKeyPair();
		
		SecretMessage secretMessage = sendSecrets(keyPair.getPublic());
		//System.out.println(secretMessage.getSecretKey());
		//System.out.println(secretMessage.getSecretMessage());
		readSecret(secretMessage, keyPair.getPrivate());
		
		
		
	}
}
