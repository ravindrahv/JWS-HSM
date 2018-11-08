package com.example.org.bouncycastle.crypto.signers;

import java.security.DigestException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPublicKey;
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
public class TestJWS {
	
	
	public static final String RSA_ENCRYPT_CIPHER_TRANSFORMATION = "RSA/ECB/NoPadding";
	public static final String RSA_SIGNATURE_SHA256_ALGORITHM = "SHA256withRSA";
	public static final String RSA_SIGNATURE_SHA256_AND_MGF1_ALGORITHM = "SHA256withRSAandMGF1";
	
	public static final String SHA256_MESSAGE_DIGEST_ALGORITHM_NAME= "SHA-256";
	
	static {
		Security.addProvider(new BouncyCastleProvider());
		System.setProperty(KeystoreHandler.SYSTEM_PROPERTY_KEY__PKCS11_CONFIG_FILE_PATH, "C:\\Ravi-2018\\Data\\java\\Nitro-HSM\\nitrohsm-sunpkcs11.cfg");
	}

	public static void main(String[] args) {
		TestJWS testJWS = new TestJWS();
		testJWS.handleTest();
	}
	
	boolean handleTest() {
		String privateKeyAlias = "hvr-nitro-key-hsm-rsa-test";
		
		String jsonString = "{1:2}";
		String serializedJWSString = handleJWSSign(jsonString, privateKeyAlias);
		boolean validationStatus = handleJWSValidate(serializedJWSString, privateKeyAlias);
		System.out.println("Validation Status : "+validationStatus);
		char[] modifiedJWSString = serializedJWSString.toCharArray();
		modifiedJWSString[modifiedJWSString.length-10] = '0';
		boolean validationStatusModified = handleJWSValidate(new String(modifiedJWSString), privateKeyAlias);
		System.out.println("Validation Status Modified: "+validationStatusModified);
		
		boolean status = (validationStatus && !validationStatusModified); 
		return status;
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
SignedInfo :GlBAGuf/CxhvmU0cWKOKfI3ush8Dcz00zfmQuUF3WHaIV4U8ZpcwzbUrvnIHxOpB3ox/7nLdWakvhh6llonymsI/jVzj6HPnhRlY5BPVq7ZSNB73wuJ7Mnirq5demDZmRlzRKoSbGba5Z+I/MBtTvRH/+i5iXd0wpKGuMy5VnxQQT2lXbqD1geDT0PV+QuQEmo1FVQIFTxpcC7ZhAcPGgTEiLqkByQAR900v/AzAAlsGqvlWEXiSBcJEl7hS77MHA7GaLjTHn67Mf8Rbeqt0+NoMPc4VuHDUFEmaWQBVMkSDZiwM2DSL+sgNGxWPajOmNB3BdxF42IriAEvCafjk8A==
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
		RSAPublicKey rsaPublicKey = (RSAPublicKey) certificate.getPublicKey();
		int modulusBitLength = rsaPublicKey.getModulus().bitLength();
		
		
		byte[] signingInput = jwsObject.getSigningInput();
		String signingInputStr = new String(signingInput);
		
		System.out.println("Modulus Bit Length :"+modulusBitLength);
		System.out.println("Signing Input :"+signingInputStr);
		
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
			
			PSSSigningBCCustomUtility pssSigningBCCustomUtility = new PSSSigningBCCustomUtility(cipher, contentDigest, mgfDigest, saltLength);
			System.out.println(privateKey.getClass());
			System.out.println("PrivateKeyEncoded :"+privateKey.getEncoded());
			pssSigningBCCustomUtility.init(true, null, null, privateKey, modulusBitLength);
			pssSigningBCCustomUtility.update(signingInput, 0, signingInput.length);
			signedInfo = pssSigningBCCustomUtility.generateSignature();
			
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
