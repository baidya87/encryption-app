package com.baidya.digest;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class BouncyCastleExamples {
	
	public static void createSymmetricKey() {
		try {
			System.out.println(Cipher.getMaxAllowedKeyLength("AES"));
			KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
			keyGenerator.init(256);
			SecretKey secretKey = keyGenerator.generateKey();
			try {
				FileWriter writer = new FileWriter(new File("certificates/symmetrickey.txt"));
				writer.write("-----A symmetric key-----\n");
				writer.write(Base64.getEncoder().encodeToString(secretKey.getEncoded()));
				writer.write("\n -----End of Key-----");
				writer.close();
			} catch (IOException e) {
				e.printStackTrace();
			}

		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
	}
	
	public static void createAsymmetricKeys() {
		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(2048);
			KeyPair keyPair = keyPairGenerator.generateKeyPair();
			FileWriter writer = new FileWriter(new File("certificates/public_and_private_keys.txt"));
			writer.write("-----A public Key-----\n");
			writer.write(Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));
			writer.write("\n-----End of public key-----\n");
			writer.write("-----A private Key-----\n");
			writer.write(Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded()));
			writer.write("\n-----End of private key-----\n");
			writer.close();
		} catch (NoSuchAlgorithmException | IOException e) {
			e.printStackTrace();
		}
		
	}

	public static void main(String[] args) {
		//createAsymmetricKeys();
		createSymmetricKey();
	}
}
