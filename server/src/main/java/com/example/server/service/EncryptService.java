package com.example.server.service;

import org.apache.commons.codec.digest.HmacUtils;
import org.springframework.stereotype.Service;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Date;

@Service
public class EncryptService {
    public static String hmacSHA256Algorithm = "HmacSHA1";
    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/CBC/PKCS5Padding";

    //этот ключ находится на сервере
    public static final String SERVER_KEY_Ks = "serverKey______s";

    public EncryptService() {
        ByteBuffer buffer = ByteBuffer.allocate(15);
    }


    public byte[] hashData(String key, String password) {
        return new HmacUtils(hmacSHA256Algorithm, key).hmac(password);
    }

    public byte[] encryptDate(long input, byte[] key, IvParameterSpec iv) throws
            NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, BadPaddingException, IllegalBlockSizeException {
        SecretKeySpec aes = new SecretKeySpec(key, ALGORITHM);
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, aes, iv);
        ByteBuffer buffer = ByteBuffer.allocate(15);
        buffer.putLong(input);
        byte[] encr = cipher.doFinal(buffer.array());
        return encr;
    }

    public Date decryptDate(byte[] input, byte[] key, IvParameterSpec iv) throws IllegalBlockSizeException,
            NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, BadPaddingException {
        SecretKeySpec aes = new SecretKeySpec(key, ALGORITHM);
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, aes, iv);
        byte[] cipherText = cipher.doFinal(input);
        ByteBuffer buffer = ByteBuffer.allocate(15);
        buffer.put(cipherText);
        buffer.flip();//need flip
        return new Date(buffer.getLong());
    }

    public byte[] encryptString(byte[] key, IvParameterSpec iv, byte[] object) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, IOException, BadPaddingException {
        SecretKeySpec aes = new SecretKeySpec(key, ALGORITHM);
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, aes, iv);
        byte[] cipherText = cipher.doFinal(object);
        return cipherText;
    }

    public byte[] decryptString(byte[] input, byte[] key,
                                IvParameterSpec iv) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {
        SecretKeySpec aes = new SecretKeySpec(key, ALGORITHM);
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, aes, iv);
        byte[] plainText = cipher.doFinal(input);
        return plainText;
    }
}
