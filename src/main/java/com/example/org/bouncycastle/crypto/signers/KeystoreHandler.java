package com.example.org.bouncycastle.crypto.signers;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
//import java.security.PublicKey;
import java.security.Provider.Service;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Scanner;
import java.util.Set;

import sun.security.pkcs11.SunPKCS11;


/**
 * <p> Keystore wrapper to hardware-encryption-device in the context of 'JWS' (JSON-Web-Signature) </p>
 * @author rhasyagar
 * @since 04-Nov-2018
 */
public class KeystoreHandler {
	
	
	
	
	/*
Name :SunPKCS11-SunPKCS11-NitroHSM
Info :SunPKCS11-SunPKCS11-NitroHSM using library C:/Program Files/OpenSC Project/OpenSC/pkcs11/opensc-pkcs11.dll

KeyFactory : RSA
Signature : SHA224withECDSA
MessageDigest : SHA-512
Signature : SHA384withRSA
Signature : SHA512withECDSA
MessageDigest : SHA-256
Cipher : RSA/ECB/PKCS1Padding
Signature : MD5withRSA
KeyAgreement : ECDH
AlgorithmParameters : EC
Signature : SHA256withECDSA
KeyPairGenerator : RSA
Signature : SHA256withRSA
Signature : NONEwithECDSA
Signature : SHA384withECDSA
KeyFactory : EC
MessageDigest : SHA1
Cipher : RSA/ECB/NoPadding
Signature : SHA224withRSA
MessageDigest : MD5
Signature : SHA1withECDSA
KeyPairGenerator : EC
MessageDigest : SHA-384
Signature : SHA512withRSA
Signature : MD2withRSA
Signature : SHA1withRSA
SecureRandom : PKCS11
KeyStore : PKCS11

	 */
	
	public static final String SYSTEM_PROPERTY_KEY__PKCS11_CONFIG_FILE_PATH = "PKCS11_CONFIG_FILE_PATH";
	public static final String KEYSTORE_TYPE = "PKCS11";
	
	private Provider provider;
	private KeyStore keyStore;
	private String keystorePassword;
	private volatile boolean init;
	
	private static KeystoreHandler keystoreHandler = new KeystoreHandler();
	
	private KeystoreHandler() {
	}
	
	Provider fetchProvider() {
		return provider;
	}
	
	static KeystoreHandler obtainClassInstance() {
		if(!keystoreHandler.init) {
			synchronized (keystoreHandler) {
				if(!keystoreHandler.init) {
					keystoreHandler.initProvider();
					keystoreHandler.keystorePassword = keystoreHandler.readKeystorePassword();
					keystoreHandler.initKeyStore();
					keystoreHandler.init=true;
				}
			}
		}
		return keystoreHandler;
	}
	
	public static void main(String[] args) {
		
		KeystoreHandler keystoreHandlerTest = KeystoreHandler.obtainClassInstance();
		
		Provider provider = keystoreHandlerTest.provider;
		System.out.println("Name :"+provider.getName());
		System.out.println("Info :"+provider.getInfo());
		
		System.out.println();
		
		Set<Service> services = provider.getServices();
		
		for (Service service : services) {
			System.out.println(service.getType()+" : "+service.getAlgorithm());
		}

	}
	
	private String readKeystorePassword() {
		String password = null;
		System.out.println("Enter password");
		Scanner scanner= null;
		try {
			scanner= new Scanner(System.in);
			password = scanner.nextLine();	
		}catch(Exception e) {
			e.printStackTrace();
		}
		
		return password;
	}
	
	private String configurationFilePath() {
		String configFilePath = System.getProperty(SYSTEM_PROPERTY_KEY__PKCS11_CONFIG_FILE_PATH);
		return configFilePath;
	}
	
	
	private void initProvider() {
		String configurationFile = configurationFilePath();
		File configFileRef = new File(configurationFile);
		FileInputStream fileInputStream = null;
		try {
			fileInputStream = new FileInputStream(configFileRef);
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		}
		
		this.provider = new SunPKCS11(fileInputStream);
	}
	
	private void initKeyStore() {
		try {
			this.keyStore = KeyStore.getInstance(KEYSTORE_TYPE, provider);
			System.out.println("Keystore Class :"+keyStore.getClass());
			keyStore.load(null, keystorePassword.toCharArray());
		} catch (KeyStoreException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (CertificateException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		
	}

	
	public PrivateKey obtainPrivateKey(String alias) {
		PrivateKey privateKey=null;
		try {
			System.out.println("Fetching private key from provider :"+keyStore.getProvider().getName());
			privateKey = (PrivateKey) keyStore.getKey(alias, keystorePassword.toCharArray());
		} catch (UnrecoverableKeyException e) {
			e.printStackTrace();
		} catch (KeyStoreException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return privateKey;
	}

	public Certificate obtainPublicKey(String alias) {
		Certificate certificate=null;
		try {
			System.out.println("Fetching private key from provider :"+keyStore.getProvider().getName());
			certificate = keyStore.getCertificate(alias);
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}
		return certificate;
	}
	
}
