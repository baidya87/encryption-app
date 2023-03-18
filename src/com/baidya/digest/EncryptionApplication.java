package com.baidya.digest;

import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class EncryptionApplication {

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
	
	public static String encodePublicKey(PublicKey key) {
		return Base64.getEncoder().encodeToString(key.getEncoded());
	}
	
	public static String encodePrivateKey(PrivateKey key) {
		return Base64.getEncoder().encodeToString(key.getEncoded());
	}
	
	public static PublicKey regeneratePublicKey(String publicKey) {
		byte[] decodeKey = Base64.getDecoder().decode(publicKey.getBytes(Charset.forName("UTF-8")));
		try {
			KeyFactory factory = KeyFactory.getInstance("RSA");
			EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(decodeKey);
			return factory.generatePublic(x509EncodedKeySpec);
		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
			e.printStackTrace();
		}
		return null;
	}
	
	public static PrivateKey regeneratePrivateKey(String privateKey) {
		byte[] decodedKey = Base64.getDecoder().decode(privateKey);
		try {
			KeyFactory factory = KeyFactory.getInstance("RSA");
			EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decodedKey);
			return factory.generatePrivate(keySpec);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		}
		return null;
	}
	
	public static String encrypt(PublicKey key, String message) {
		try {
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, key);
			return Base64.getEncoder().encodeToString(cipher.doFinal(message.getBytes(Charset.forName("UTF-8"))));
			
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		}
		return null;
	}
	
	public static void decrypt(PrivateKey key, String encryptedMessage) {
		try {
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, key);
			byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedMessage.getBytes(Charset.forName("UTF-8"))));
			System.out.println(new String(decryptedBytes, Charset.forName("UTF-8")));
			
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
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
		String message = "Hello ! this is a long long movie. Get me pop-corns";
		KeyPair keyPair = generateKeyPair();
		//String encryptedString = encrypt(keyPair.getPublic(), message);
		//System.out.println(encryptedString);
		//decrypt(keyPair.getPrivate(), encryptedString);
		System.out.println("----------------------------------------------------------------------------------------");
		
		//System.out.println("Encrypted public key : "+encodePublicKey(keyPair.getPublic()));
		String encodePublicKey = encodePublicKey(keyPair.getPublic());
		String encodePrivateKey = encodePrivateKey(keyPair.getPrivate());
		
		String encryptedMessage = encrypt(regeneratePublicKey(encodePublicKey), message);
		decrypt(regeneratePrivateKey(encodePrivateKey), encryptedMessage);
		
	}
}
