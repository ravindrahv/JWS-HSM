package com.example.org.bouncycastle.crypto.signers;

import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

public class TestJWSHSM_JUnit {
	
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

	@Test
	void test() {
		//fail("Not yet implemented");
		TestJWS testJWS = new TestJWS();
		boolean result = testJWS.handleTest();
		assertTrue(result);
	}

}
