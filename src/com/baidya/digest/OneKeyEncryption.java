package com.baidya.digest;

import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

/**
 * Using a single key for encryption. (symmetric)
 * @author baidya
 *
 */
public class OneKeyEncryption {

	public static SecretKey generateKey() {
		try {
			KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
			keyGenerator.init(128);
			return keyGenerator.generateKey();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return null;
	}
	
	public static void main(String[] args) {
		SecretKey key = generateKey();
		try {
			Cipher cipher = Cipher.getInstance("AES");
			cipher.init(Cipher.ENCRYPT_MODE, key);
			byte[] encryptedMsg = cipher.doFinal("Hello World of encryption!!".getBytes(Charset.forName("UTF-8")));
			System.out.println("__________ENCRYPT___________");
			System.out.println(Base64.getEncoder().encodeToString(encryptedMsg));
			System.out.println("__________DECRYPT___________");
			cipher.init(Cipher.DECRYPT_MODE, key);
			byte[] decryptedMsg = cipher.doFinal(encryptedMsg);
			System.out.println(new String(decryptedMsg, Charset.forName("UTF-8")));
			
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
}
