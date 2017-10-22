package com.emc.clb;

import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.Map.Entry;
import java.util.Properties;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class LockBox {

	private static SecretKeySpec createSecretKey(char[] password, byte[] salt, int iterationCount, int keyLength) throws NoSuchAlgorithmException, InvalidKeySpecException {
		SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
		PBEKeySpec keySpec = new PBEKeySpec(password, salt, iterationCount, keyLength);
		SecretKey keyTmp = keyFactory.generateSecret(keySpec);
		return new SecretKeySpec(keyTmp.getEncoded(), "AES");
	}

	private static String encrypt(String property, SecretKeySpec key) throws GeneralSecurityException, UnsupportedEncodingException {
		Cipher pbeCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		pbeCipher.init(Cipher.ENCRYPT_MODE, key);
		AlgorithmParameters parameters = pbeCipher.getParameters();
		IvParameterSpec ivParameterSpec = parameters.getParameterSpec(IvParameterSpec.class);
		byte[] cryptoText = pbeCipher.doFinal(property.getBytes("UTF-8"));
		byte[] iv = ivParameterSpec.getIV();
		return base64Encode(iv) + ":" + base64Encode(cryptoText);
	}

	private static String base64Encode(byte[] bytes) {
		return Base64.getEncoder().encodeToString(bytes);
	}

	private static String decrypt(String string, SecretKeySpec key) throws GeneralSecurityException, IOException {
		String iv = string.split(":")[0];
		String property = string.split(":")[1];
		Cipher pbeCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		pbeCipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(base64Decode(iv)));
		return new String(pbeCipher.doFinal(base64Decode(property)), "UTF-8");
	}

	private static byte[] base64Decode(String property) throws IOException {
		return Base64.getDecoder().decode(property);
	}
	

	private Properties _props = new Properties();	
	private SecretKeySpec _key;

	public LockBox(String sFilePath, String sPassphrase) throws IOException {
		InputStream is = getClass().getClassLoader().getResourceAsStream("easy_lockbox.properties");
		try {
			_props.load(is);
		}
		finally {
			is.close();
		}

		byte[] salt = new String("fhkjzf489rno4").getBytes();
        try {
			_key = createSecretKey(getClass().getCanonicalName().toCharArray(), salt, 1000, 127);
		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
			throw new IOException(e);
		}
	}


	public String retrieveItemAsText(String sKey) {
		String s = _props.getProperty(sKey);
		if(s != null && s.length() != 0 && s.startsWith("$enc$"))
			try {
				s = decrypt(s.substring(5), _key);
			} catch (GeneralSecurityException | IOException e) {
				throw new IllegalStateException(e);
			}
		return s;
	}

	public void closeLockbox() {
	}
	
	
	public void printEncrypted() throws UnsupportedEncodingException, GeneralSecurityException {
		for(Entry<Object, Object> e : _props.entrySet()) {
			String s = (String) e.getValue();
			if(s != null && s.length() != 0 && !s.startsWith("$enc$"))
				s = "$enc$" + encrypt(s.substring(5), _key);
				
			System.out.println(e.getKey() + "=" + s);
		}
	}
	
	
	public static void main(String[] saArg) throws IOException, GeneralSecurityException {
		LockBox lb = new LockBox(null, null);
		lb.printEncrypted();
	}

}
