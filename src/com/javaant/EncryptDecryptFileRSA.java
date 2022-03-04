package com.javaant;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.Cipher;

import org.apache.commons.io.FileUtils;

class MyRSACipher {
	public static KeyPair getRSAKeyPair() throws NoSuchAlgorithmException {
		KeyPairGenerator keypairgenerator = KeyPairGenerator.getInstance("RSA");
		keypairgenerator.initialize(2048);
		KeyPair keypair = keypairgenerator.generateKeyPair();
		return keypair;
	}

	public static byte[] encryptFile(byte[] inputBytes, PublicKey key, String xform) throws Exception {
		Cipher cipher = Cipher.getInstance(xform);
		cipher.init(Cipher.ENCRYPT_MODE, key);
		return cipher.doFinal(inputBytes);
	}

	public static byte[] decryptFile(byte[] inputBytes, PrivateKey key, String xform) throws Exception {
		Cipher cipher = Cipher.getInstance(xform);
		cipher.init(Cipher.DECRYPT_MODE, key);
		return cipher.doFinal(inputBytes);
	}
}

public class EncryptDecryptFileRSA {
	public static void main(String[] args) throws Exception {

		
		String fileToEncrypt = "C:/Users/Desktop/Encrypt-Decrypt-File-RSA-master/original-file";
		String encryptedFile = "C:/Users/Desktop/Encrypt-Decrypt-File-RSA-master/file-after-encryption";
		String decryptedFile = "C:/Users/Desktop/Encrypt-Decrypt-File-RSA-master/file-after-decryption";
		byte[] encryptedBytes = null;
		String algo = "RSA/ECB/PKCS1Padding";
		

		KeyPair keyPari = MyRSACipher.getRSAKeyPair();
		PublicKey publicKey = keyPari.getPublic();
		PrivateKey privatekey = keyPari.getPrivate();
		
		    String string = keyPari.toString();
		    BufferedWriter writer = new BufferedWriter(new FileWriter("Encyption key.txt"));
		    writer.write(string);
		    writer.close();
	

		File file = new File(fileToEncrypt);
		byte[] dataBytes = FileUtils.readFileToByteArray(file);

		System.out.println("Press 0 For Encrypt ");
		System.out.println("Press 1 For Decrypt");
		java.util.Scanner scn=new java.util.Scanner(System.in);
		int select=scn.nextInt();
		if (select==0)
		{
			

			
			encryptedBytes = MyRSACipher.encryptFile(dataBytes, publicKey, algo);
			file = new File(encryptedFile);
			FileUtils.writeByteArrayToFile(file, encryptedBytes);
			System.out.println("Encrypted file : " + encryptedFile);
	
			
	
		}
		else if(select==1)
		{
			
			
			encryptedBytes = MyRSACipher.encryptFile(dataBytes, publicKey, algo);
			file = new File(encryptedFile);
			FileUtils.writeByteArrayToFile(file, encryptedBytes);
			byte[] decryptedBytes = MyRSACipher.decryptFile(encryptedBytes, privatekey, algo);
			file = new File(decryptedFile);
			FileUtils.writeByteArrayToFile(file, decryptedBytes);
			System.out.println("Decrypted file : " + decryptedFile);

		}
		else
		{
			System.out.println("Invalid ");
		}
		

	}

}
