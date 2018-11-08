package com.example.org.bouncycastle.crypto.signers;

import java.security.DigestException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.text.ParseException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.xml.bind.DatatypeConverter;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.util.Base64URL;

/**
 * <p> Test harness to validate RSA-PSS-MGF1 Scheme. </p>
 * @author rhasyagar
 * @since 05-Nov-2018
 *
 */
public class TestJWS_POC {
	
	
	public static final String RSA_ENCRYPT_CIPHER_TRANSFORMATION = "RSA/ECB/NoPadding";
	public static final String RSA_SIGNATURE_SHA256_ALGORITHM = "SHA256withRSA";
	public static final String RSA_SIGNATURE_SHA256_AND_MGF1_ALGORITHM = "SHA256withRSAandMGF1";
	
	public static final String SHA256_MESSAGE_DIGEST_ALGORITHM_NAME= "SHA-256";
	
	static {
		Security.addProvider(new BouncyCastleProvider());
		System.setProperty(KeystoreHandler.SYSTEM_PROPERTY_KEY__PKCS11_CONFIG_FILE_PATH, "C:\\Ravi-2018\\Data\\java\\Nitro-HSM\\nitrohsm-sunpkcs11.cfg");
	}

	public static void main(String[] args) {
		TestJWS_POC testJWS = new TestJWS_POC();
		String privateKeyAlias = "hvr-nitro-key-hsm-rsa-test";
		
		String jsonString = "{1:2}";
		String serializedJWSString = testJWS.handleJWSSign(jsonString, privateKeyAlias);
		boolean validationStatus = testJWS.handleJWSValidate(serializedJWSString, privateKeyAlias);
		System.out.println("Validation Status : "+validationStatus);
//		testJWS.handleJWSSignTwo(jsonString, privateKeyAlias);
//		testJWS.handleJWSSignThree(jsonString, privateKeyAlias);
		char[] modifiedJWSString = serializedJWSString.toCharArray();
		modifiedJWSString[modifiedJWSString.length-10] = '0';
		boolean validationStatusModified = testJWS.handleJWSValidate(new String(modifiedJWSString), privateKeyAlias);
		System.out.println("Validation Status Modified: "+validationStatusModified);


	}
	
	
	private PrivateKey fetchPrivateKeyFromHSM(String alias) {
		KeystoreHandler keystoreHandler = KeystoreHandler.obtainClassInstance();
		PrivateKey privateKey = keystoreHandler.obtainPrivateKey(alias);
		return privateKey;
	}
	
	
	
	/*
Enter password
******
Keystore Class :class java.security.KeyStore
Fetching private key from provider :SunPKCS11-SunPKCS11-NitroHSM
Fetching private key from provider :SunPKCS11-SunPKCS11-NitroHSM
Modulus Bit Length :2048
Signing Input :eyJhbGciOiJQUzI1NiJ9.ezE6Mn0
class sun.security.pkcs11.P11Key$P11PrivateKey
PrivateKeyEncoded :null
Block Length :256
SignedInfo :HeEwJtEhu4X0aM/4ki/BEM5SWOcDu6/WvtUUr1mGCsqs5WnW0e88OMZueWGQV5ZTed86bMmnYKVuC6Mn+kPm+Tx6dhnZrHV+379/aQ+X9ApOr55G0RaXjJNTPAWlKSyAA/XLQfceEvXo+RFCVRagpj3M05//msZNIyiNrT1qpW0tEaIlApDc08CEAIXOXfCfSv0Em022PiAQpnvBqJx6xCl+NO9jrlYxHnTRxwd38CSXIfwGQbKLeiTOvefk9veGkbnDRAxlfO9tkvqPtakcvhU5W79cmnEThrAMGp496xbR35ifEFQ4h+/Uod6x5o/A7Abb7zElmaRUGo8EQ2Zf6A==
Fetching private key from provider :SunPKCS11-SunPKCS11-NitroHSM
Verification Status :true
Validation Status : true
Fetching private key from provider :SunPKCS11-SunPKCS11-NitroHSM
Verification Status :false
Validation Status Modified: false
	 */
	
	/**
	 * @param jsonString
	 * @param privateKeyAlias
	 */
	private String handleJWSSign(String jsonString, String privateKeyAlias) {
		
		JWSHeader header = new JWSHeader(JWSAlgorithm.PS256);
		Payload payload = new Payload(jsonString);
		
		JWSObject jwsObject = new JWSObject(header, payload);
		PrivateKey privateKey = fetchPrivateKeyFromHSM(privateKeyAlias);
		Certificate certificate = KeystoreHandler.obtainClassInstance().obtainPublicKey(privateKeyAlias);
//		X509Certificate x509Certificate = (X509Certificate) certificate; 
		RSAPublicKey rsaPublicKey = (RSAPublicKey) certificate.getPublicKey();
		int modulusBitLength = rsaPublicKey.getModulus().bitLength();
		
//		RSASSASigner rsassaSigner = new RSASSASigner(privateKey);
//		rsassaSigner.getJCAContext().setProvider(KeystoreHandler.obtainClassInstance().fetchProvider());
		
		byte[] signingInput = jwsObject.getSigningInput();
		String signingInputStr = new String(signingInput);
		
		System.out.println("Modulus Bit Length :"+modulusBitLength);
		System.out.println("Signing Input :"+signingInputStr);
		/*
		try {
			jwsObject.sign(rsassaSigner);
		} catch (JOSEException e) {
			e.printStackTrace();
		}
		*/
		
		
//		String signedJWS = jwsObject.serialize();
		
//		System.out.println(signedJWS);
		
		MessageDigest contentDigest = null;
		MessageDigest mgfDigest = null;
		int saltLength = -1;
		Cipher cipher = null;
		byte[] signedInfo = null;
		try {
			contentDigest = MessageDigest.getInstance(SHA256_MESSAGE_DIGEST_ALGORITHM_NAME);
			mgfDigest = MessageDigest.getInstance(SHA256_MESSAGE_DIGEST_ALGORITHM_NAME);
			saltLength = mgfDigest.getDigestLength();
			cipher = Cipher.getInstance(RSA_ENCRYPT_CIPHER_TRANSFORMATION, KeystoreHandler.obtainClassInstance().fetchProvider());
			
			PSSSigningBCCustomUtility_POC pssSigningBCCustomUtility_Source = new PSSSigningBCCustomUtility_POC(cipher, contentDigest, mgfDigest, saltLength);
			System.out.println(privateKey.getClass());
			System.out.println("PrivateKeyEncoded :"+privateKey.getEncoded());
			pssSigningBCCustomUtility_Source.init(true, null, null, privateKey, modulusBitLength);
			pssSigningBCCustomUtility_Source.update(signingInput, 0, signingInput.length);
			signedInfo = pssSigningBCCustomUtility_Source.generateSignature();
			
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		} catch (DigestException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		}
		
		System.out.println("SignedInfo :"+DatatypeConverter.printBase64Binary(signedInfo));
		Base64URL base64urlSignedInfo = Base64URL.encode(signedInfo);
		
		String serializedJWSObject = buildSignedJWSString(signingInputStr, base64urlSignedInfo.toString());
		
		JWSObject jwsObjectTwo=null;
		String result = null;
		try {
			jwsObjectTwo = JWSObject.parse(serializedJWSObject);
			result = jwsObjectTwo.serialize(); 
		} catch (ParseException e) {
			e.printStackTrace();
		}

		return result;
		
	}
	
	private String buildSignedJWSString(String signingInput, String base64EncodedSignature) {
		StringBuilder jwsSignedInfo = new StringBuilder();
		jwsSignedInfo.append(signingInput);
		jwsSignedInfo.append(".");
		jwsSignedInfo.append(base64EncodedSignature);
		
		return jwsSignedInfo.toString();
	}
	
	
	/*
java.security.InvalidAlgorithmParameterException: Parameters not supported
	at sun.security.pkcs11.P11RSACipher.engineInit(P11RSACipher.java:177)
	at javax.crypto.Cipher.init(Cipher.java:1393)
	at javax.crypto.Cipher.init(Cipher.java:1326)
	at com.example.jws.test.TestJWS.handleJWSSignTwo(TestJWS.java:169)
	 */
	/**
	 * @deprecated
	 * @param jsonString
	 * @param privateKeyAlias
	 */
	private void handleJWSSignTwo(String jsonString, String privateKeyAlias) {
		
		JWSHeader header = new JWSHeader(JWSAlgorithm.PS256);
		Payload payload = new Payload(jsonString);
		
		JWSObject jwsObject = new JWSObject(header, payload);
		PrivateKey privateKey = fetchPrivateKeyFromHSM(privateKeyAlias);
		
		byte[] signingInput = jwsObject.getSigningInput();
		
		System.out.println("Signing Input :"+new String(signingInput));
		Cipher cipher = null;
		byte[] signedInfo = null;
		try {
			cipher = Cipher.getInstance(RSA_ENCRYPT_CIPHER_TRANSFORMATION, KeystoreHandler.obtainClassInstance().fetchProvider());
			PSSParameterSpec pssParameterSpec = new PSSParameterSpec("SHA256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
			cipher.init(Cipher.ENCRYPT_MODE, privateKey, pssParameterSpec);
			
			signedInfo = cipher.doFinal(signingInput);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		}
		
		System.out.println("SignedInfo :"+DatatypeConverter.printBase64Binary(signedInfo));
		
	}

	
	/*
Exception in thread "main" java.lang.UnsupportedOperationException
	at java.security.SignatureSpi.engineSetParameter(SignatureSpi.java:324)
	at java.security.Signature$Delegate.engineSetParameter(Signature.java:1240)
	at java.security.Signature.setParameter(Signature.java:870)
	at com.example.jws.test.TestJWS.handleJWSSignThree(TestJWS.java:196)
	 */
	/**
	 * @deprecated
	 */
	private void handleJWSSignThree(String jsonString, String privateKeyAlias) {
		
		JWSHeader header = new JWSHeader(JWSAlgorithm.PS256);
		Payload payload = new Payload(jsonString);
		
		JWSObject jwsObject = new JWSObject(header, payload);
		PrivateKey privateKey = fetchPrivateKeyFromHSM(privateKeyAlias);
		
		byte[] signingInput = jwsObject.getSigningInput();
		
		System.out.println("Signing Input :"+new String(signingInput));
		Signature signature = null;
		byte[] signedInfo = null;
		try {
			signature = Signature.getInstance(RSA_SIGNATURE_SHA256_ALGORITHM, KeystoreHandler.obtainClassInstance().fetchProvider());
			PSSParameterSpec pssParameterSpec = new PSSParameterSpec("SHA256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
			signature.setParameter(pssParameterSpec);
			signature.initSign(privateKey);
			signature.update(signingInput);
			signedInfo = signature.sign();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		} catch (SignatureException e) {
			e.printStackTrace();
		}
		
		System.out.println("SignedInfo :"+DatatypeConverter.printBase64Binary(signedInfo));
		
	}
	
	private boolean handleJWSValidate(String serializedJWS, String certificateAlias) {
		boolean result = false;
		
		try {
			JWSObject jwsObject = JWSObject.parse(serializedJWS);
			Certificate certificate = KeystoreHandler.obtainClassInstance().obtainPublicKey(certificateAlias);
			RSAPublicKey rsaPublicKey = (RSAPublicKey) certificate.getPublicKey();
			
			RSASSAVerifier rsassaVerifier = new RSASSAVerifier(rsaPublicKey);
			rsassaVerifier.getJCAContext().setProvider(new BouncyCastleProvider());
			result = jwsObject.verify(rsassaVerifier);
			
			System.out.println("Verification Status :"+result);
			
			
		} catch (ParseException e) {
			e.printStackTrace();
		} catch (JOSEException e) {
			e.printStackTrace();
		}
		
		return result;
		
	}

}
