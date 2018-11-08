package com.example.org.bouncycastle.crypto.signers;

import java.security.DigestException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
//import java.security.spec.RSAPrivateKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;

/*
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.RSABlindingParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
*/

/**
 * <p> Problem Statement : Intended to be used in scenarios where there is no native support on hardware-encryption-device (SmartToken/HSM) platforms for advanced RSA-PSS-MGF1 
 * signing schemes.</p>
 * 
 * <p>One example is 'PS256' from 'JWS' (JSON-Web-Signature) which translates to 'SHA256withRSAandMGF1'. The approach is to first perform sha2-XXX hashing along with mgf1-XXX-salt-hash padding 
 * in the application layer and then provide the result as input to the hardware-encryption-device as a plain string to be rsa-encrypted.</p>
 * 
 * <p> RSA-PSS-MGF1-Signer intended to be used for 'JWS' along with PKCS11 interface based hardware-encryption-device (SmartToken/HSM) </p>
 * <p> For more information on JWS, refer <i>https://tools.ietf.org/html/rfc7515 </i></p>
 * 
 * @author rhasyagar (Refactored BouncyCastle's 'org.bouncycastle.crypto.signers.PSSSigner' for use with 'javax.crypto.Cipher' and 'java.security.MessageDigest' )
 * @since 04-Nov-2018
 * 
 * RSA-PSS as described in PKCS# 1 v 2.1.
 * <p>
 * Note: the usual value for the salt length is the number of
 * bytes in the hash function.
 */
public class PSSSigningBCCustomUtility_POC
{
	public static final String SECURE_RANDOM_ALGORITHM_NAME = "PKCS11";
    static final public byte   TRAILER_IMPLICIT    = (byte)0xBC;

    /*-NIMBUS-JOSE-JWS-Nov2018-*/
    /*
    private Digest                      contentDigest;
    private Digest                      mgfDigest;
    private AsymmetricBlockCipher       cipher;
    */
    private MessageDigest contentDigest; // NIMBUS-JOSE-JWS-Nov2018
    private MessageDigest mgfDigest; // NIMBUS-JOSE-JWS-Nov2018
    private Cipher cipher; // NIMBUS-JOSE-JWS-Nov2018
    
    private SecureRandom                random;

    private int                         hLen;
    private int                         mgfhLen;
    private boolean                     sSet; // salt-provided
    private int                         sLen; // salt-length
    private int                         emBits;
    private byte[]                      salt;
    private byte[]                      mDash;
    private byte[]                      block;
    private byte                        trailer;

    /*
    /-**
     * basic constructor
     *
     * @param cipher the asymmetric cipher to use.
     * @param digest the digest to use.
     * @param sLen the length of the salt to use (in bytes).
     *-/
    public BCCustomPSSSigner(
        AsymmetricBlockCipher   cipher,
        Digest                  digest,
        int                     sLen)
    {
        this(cipher, digest, sLen, TRAILER_IMPLICIT);
    }
    
    */
    
    /**
     * basic constructor
     *
     * @param cipher the asymmetric cipher to use.
     * @param digest the digest to use.
     * @param sLen the length of the salt to use (in bytes).
     */
    public PSSSigningBCCustomUtility_POC(
        Cipher   cipher,
        MessageDigest                  digest,
        int                     sLen)
    {
        this(cipher, digest, sLen, TRAILER_IMPLICIT);
    }
    

    /*
    public BCCustomPSSSigner(
        AsymmetricBlockCipher   cipher,
        Digest                  contentDigest,
        Digest                  mgfDigest,
        int                     sLen)
    {
        this(cipher, contentDigest, mgfDigest, sLen, TRAILER_IMPLICIT);
    }
    */
    
    public PSSSigningBCCustomUtility_POC(
            Cipher   cipher,
            MessageDigest                  contentDigest,
            MessageDigest                  mgfDigest,
            int                     sLen)
        {
            this(cipher, contentDigest, mgfDigest, sLen, TRAILER_IMPLICIT);
        }
    

    /*
    public BCCustomPSSSigner(
            AsymmetricBlockCipher   cipher,
            Digest                  digest,
            int                     sLen,
            byte                    trailer)
    {
        this(cipher, digest, digest, sLen, trailer);
    }
    */
    public PSSSigningBCCustomUtility_POC(
            Cipher   cipher,
            MessageDigest                  digest,
            int                     sLen,
            byte                    trailer)
    {
        this(cipher, digest, digest, sLen, trailer);
    }
    

    /*
    public BCCustomPSSSigner(
        AsymmetricBlockCipher   cipher,
        Digest                  contentDigest,
        Digest                  mgfDigest,
        int                     sLen,
        byte                    trailer)
    {
        this.cipher = cipher;
        this.contentDigest = contentDigest;
        this.mgfDigest = mgfDigest;
        this.hLen = contentDigest.getDigestSize();
        this.mgfhLen = mgfDigest.getDigestSize();
        this.sSet = false;
        this.sLen = sLen;
        this.salt = new byte[sLen];
        this.mDash = new byte[8 + sLen + hLen];
        this.trailer = trailer;
    }
    */

    public PSSSigningBCCustomUtility_POC(
            Cipher   cipher,
            MessageDigest                  contentDigest,
            MessageDigest                  mgfDigest,
            int                     sLen,
            byte                    trailer)
        {
            this.cipher = cipher;
            this.contentDigest = contentDigest;
            this.mgfDigest = mgfDigest;
//            this.hLen = contentDigest.getDigestSize();
//            this.mgfhLen = mgfDigest.getDigestSize();
            this.hLen = contentDigest.getDigestLength();
            this.mgfhLen = mgfDigest.getDigestLength();
            this.sSet = false;
            this.sLen = sLen;
            this.salt = new byte[sLen];
            this.mDash = new byte[8 + sLen + hLen];
            this.trailer = trailer;
        }

    /*
    public BCCustomPSSSigner(
        AsymmetricBlockCipher   cipher,
        Digest                  digest,
        byte[]                  salt)
    {
        this(cipher, digest, digest, salt, TRAILER_IMPLICIT);
    }
    */
    public PSSSigningBCCustomUtility_POC(
            Cipher   cipher,
            MessageDigest                  digest,
            byte[]                  salt)
        {
            this(cipher, digest, digest, salt, TRAILER_IMPLICIT);
        }
    

    /*
    public BCCustomPSSSigner(
        AsymmetricBlockCipher   cipher,
        Digest                  contentDigest,
        Digest                  mgfDigest,
        byte[]                  salt)
    {
        this(cipher, contentDigest, mgfDigest, salt, TRAILER_IMPLICIT);
    }
    */
    
    public PSSSigningBCCustomUtility_POC(
            Cipher   cipher,
            MessageDigest                  contentDigest,
            MessageDigest                  mgfDigest,
            byte[]                  salt)
        {
            this(cipher, contentDigest, mgfDigest, salt, TRAILER_IMPLICIT);
        }

    /*
    public BCCustomPSSSigner(
        AsymmetricBlockCipher   cipher,
        Digest                  contentDigest,
        Digest                  mgfDigest,
        byte[]                  salt,
        byte                    trailer)
    {
        this.cipher = cipher;
        this.contentDigest = contentDigest;
        this.mgfDigest = mgfDigest;
        this.hLen = contentDigest.getDigestSize();
        this.mgfhLen = mgfDigest.getDigestSize();
        this.sSet = true;
        this.sLen = salt.length;
        this.salt = salt;
        this.mDash = new byte[8 + sLen + hLen];
        this.trailer = trailer;
    }
    */
    public PSSSigningBCCustomUtility_POC(
            Cipher   cipher,
            MessageDigest                  contentDigest,
            MessageDigest                  mgfDigest,
            byte[]                  salt,
            byte                    trailer)
        {
            this.cipher = cipher;
            this.contentDigest = contentDigest;
            this.mgfDigest = mgfDigest;
//            this.hLen = contentDigest.getDigestSize();
//            this.mgfhLen = mgfDigest.getDigestSize();
            this.hLen = contentDigest.getDigestLength();
            this.mgfhLen = mgfDigest.getDigestLength();
            this.sSet = true;
            this.sLen = salt.length;
            this.salt = salt;
            this.mDash = new byte[8 + sLen + hLen];
            this.trailer = trailer;
        }
    

    /*
    public void init(
        boolean                 forSigning,
        CipherParameters        param)
    {
        CipherParameters  params;

        if (param instanceof ParametersWithRandom)
        {
            ParametersWithRandom    p = (ParametersWithRandom)param;

            params = p.getParameters();
            random = p.getRandom();
        }
        else
        {
            params = param;
            if (forSigning)
            {
                random = CryptoServicesRegistrar.getSecureRandom();
            }
        }

        RSAKeyParameters kParam;

        if (params instanceof RSABlindingParameters)
        {
            kParam = ((RSABlindingParameters)params).getPublicKey();

            cipher.init(forSigning, param);   // pass on random
        }
        else
        {
            kParam = (RSAKeyParameters)params;

            cipher.init(forSigning, params);
        }
        
        emBits = kParam.getModulus().bitLength() - 1;

        if (emBits < (8 * hLen + 8 * sLen + 9))
        {
            throw new IllegalArgumentException("key too small for specified hash and salt lengths");
        }

        block = new byte[(emBits + 7) / 8];

        reset();
    }
    
    */
    
    public void init(
    		boolean	forSigning,
            AlgorithmParameterSpec	params, 
            SecureRandom	secureRandom,
            PrivateKey key, int modulusBitLength) throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException
        {
    	
    		int cipherMode = (forSigning) ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE; 
    		
	    	if(secureRandom != null) {
	    		random = secureRandom;
	    	} else {
	    		random = SecureRandom.getInstance(SECURE_RANDOM_ALGORITHM_NAME, cipher.getProvider());
	    	}

            if(params!=null) {
            	cipher.init(cipherMode, key, params);	
            }else {
            	cipher.init(cipherMode, key);
            }
            
            
//            PrivateKey privateKey = key;
//            System.out.println("KeyFormat :"+privateKey.getFormat());
//            printClassHierarchy(key.getClass());
//            RSAPrivateKeySpec rsaPrivateKeySpec = (RSAPrivateKeySpec) key;
            emBits =  modulusBitLength - 1;

            if (emBits < (8 * hLen + 8 * sLen + 9))
            {
                throw new IllegalArgumentException("key too small for specified hash and salt lengths");
            }

            block = new byte[(emBits + 7) / 8];
            System.out.println("Block Length :"+block.length);
            reset();
        }
    

    /**
     * clear possible sensitive data
     */
    private void clearBlock(
        byte[]  block)
    {
        for (int i = 0; i != block.length; i++)
        {
            block[i] = 0;
        }
    }

    /**
     * update the internal digest with the byte b
     */
    public void update(
        byte    b)
    {
        contentDigest.update(b);
    }

    /**
     * update the internal digest with the byte array in
     */
    public void update(
        byte[]  in,
        int     off,
        int     len)
    {
        contentDigest.update(in, off, len);
    }

    /**
     * reset the internal state
     */
    public void reset()
    {
        contentDigest.reset();
    }

    /**
     * generate a signature for the message we've been loaded with using
     * the key we were initialised with.
     * @throws BadPaddingException 
     * @throws IllegalBlockSizeException 
     * @throws DigestException 
     */
    public byte[] generateSignature() throws IllegalBlockSizeException, BadPaddingException, DigestException
        /*throws CryptoException, DataLengthException*/
    {
        //contentDigest.doFinal(mDash, mDash.length - hLen - sLen);
    	contentDigest.digest(mDash, mDash.length - hLen - sLen, (hLen + sLen));

        if (sLen != 0)
        {
            if (!sSet)
            {
                random.nextBytes(salt);
            }

            System.arraycopy(salt, 0, mDash, mDash.length - sLen, sLen);
        }

        byte[]  h = new byte[hLen];

        contentDigest.update(mDash, 0, mDash.length);

        //contentDigest.doFinal(h, 0);
        contentDigest.digest(h, 0, h.length);

        block[block.length - sLen - 1 - hLen - 1] = 0x01;
        System.arraycopy(salt, 0, block, block.length - sLen - hLen - 1, sLen);

        byte[] dbMask = maskGeneratorFunction1(h, 0, h.length, block.length - hLen - 1);
        for (int i = 0; i != dbMask.length; i++)
        {
            block[i] ^= dbMask[i];
        }

        block[0] &= (0xff >> ((block.length * 8) - emBits));

        System.arraycopy(h, 0, block, block.length - hLen - 1, hLen);

        block[block.length - 1] = trailer;

//        byte[]  b = cipher.processBlock(block, 0, block.length);
        byte[]  b = cipher.doFinal(block, 0, block.length);

        clearBlock(block);

        return b;
    }

    /**
     * return true if the internal state represents the signature described
     * in the passed in array.
     * @throws DigestException 
     */
    public boolean verifySignature(
        byte[]      signature) throws DigestException
    {
//        contentDigest.doFinal(mDash, mDash.length - hLen - sLen);
    	contentDigest.digest(mDash, mDash.length - hLen - sLen, (hLen + sLen));

        try
        {
//            byte[] b = cipher.processBlock(signature, 0, signature.length);
        	byte[] b = cipher.doFinal(signature, 0, signature.length);
            System.arraycopy(b, 0, block, block.length - b.length, b.length);
        }
        catch (Exception e)
        {
            return false;
        }

        if (block[block.length - 1] != trailer)
        {
            clearBlock(block);
            return false;
        }

        byte[] dbMask = maskGeneratorFunction1(block, block.length - hLen - 1, hLen, block.length - hLen - 1);

        for (int i = 0; i != dbMask.length; i++)
        {
            block[i] ^= dbMask[i];
        }

        block[0] &= (0xff >> ((block.length * 8) - emBits));

        for (int i = 0; i != block.length - hLen - sLen - 2; i++)
        {
            if (block[i] != 0)
            {
                clearBlock(block);
                return false;
            }
        }

        if (block[block.length - hLen - sLen - 2] != 0x01)
        {
            clearBlock(block);
            return false;
        }

        if (sSet)
        {
            System.arraycopy(salt, 0, mDash, mDash.length - sLen, sLen);
        }
        else
        {
            System.arraycopy(block, block.length - sLen - hLen - 1, mDash, mDash.length - sLen, sLen);
        }

        contentDigest.update(mDash, 0, mDash.length);
        //contentDigest.doFinal(mDash, mDash.length - hLen);
        contentDigest.digest(mDash, mDash.length - hLen,hLen);

        for (int i = block.length - hLen - 1, j = mDash.length - hLen;
                                                 j != mDash.length; i++, j++)
        {
            if ((block[i] ^ mDash[j]) != 0)
            {
                clearBlock(mDash);
                clearBlock(block);
                return false;
            }
        }

        clearBlock(mDash);
        clearBlock(block);

        return true;
    }

    /**
     * int to octet string.
     */
    private void ItoOSP(
        int     i,
        byte[]  sp)
    {
        sp[0] = (byte)(i >>> 24);
        sp[1] = (byte)(i >>> 16);
        sp[2] = (byte)(i >>> 8);
        sp[3] = (byte)(i >>> 0);
    }

    /**
     * mask generator function, as described in PKCS1v2.
     * @throws DigestException 
     */
    private byte[] maskGeneratorFunction1(
        byte[]  Z,
        int     zOff,
        int     zLen,
        int     length) throws DigestException
    {
        byte[]  mask = new byte[length];
        byte[]  hashBuf = new byte[mgfhLen];
        byte[]  C = new byte[4];
        int     counter = 0;

        mgfDigest.reset();

        while (counter < (length / mgfhLen))
        {
            ItoOSP(counter, C);

            mgfDigest.update(Z, zOff, zLen);
            mgfDigest.update(C, 0, C.length);
            //mgfDigest.doFinal(hashBuf, 0);
            mgfDigest.digest(hashBuf, 0, hashBuf.length);

            System.arraycopy(hashBuf, 0, mask, counter * mgfhLen, mgfhLen);

            counter++;
        }

        if ((counter * mgfhLen) < length)
        {
            ItoOSP(counter, C);

            mgfDigest.update(Z, zOff, zLen);
            mgfDigest.update(C, 0, C.length);
            //mgfDigest.doFinal(hashBuf, 0);
            mgfDigest.digest(hashBuf, 0, hashBuf.length);

            System.arraycopy(hashBuf, 0, mask, counter * mgfhLen, mask.length - (counter * mgfhLen));
        }

        return mask;
    }
    
    /*
    private static void printClassHierarchy(Class classType) {
    	Class tempClass = classType;
    	while(Object.class != tempClass) {
    		System.out.println("Class : "+tempClass.getName());
    		tempClass = tempClass.getSuperclass();
    	}
    }
    */
}
