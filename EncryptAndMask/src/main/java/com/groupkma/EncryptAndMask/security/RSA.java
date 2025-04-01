/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */

package com.groupkma.EncryptAndMask.security;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import org.springframework.stereotype.Component;

/**
 *
 * @author minhp
 */

@Component
public class RSA {
    private static final BigInteger ZERO = BigInteger.ZERO;
    private static final BigInteger ONE = BigInteger.ONE;
    private static final BigInteger TWO = BigInteger.TWO;
    private static final BigInteger THREE = new BigInteger("3");
    private static final int KEY_SIZE = 512;
    
    public boolean isProbablePrime(BigInteger n, int k) {
        if (n.compareTo(ONE) == 0)
            return false;
        if (n.compareTo(THREE) < 0)
            return true;
        int s = 0;
        BigInteger d = n.subtract(ONE);
        while (d.mod(TWO).equals(ZERO)) {
            s++;
            d = d.divide(TWO);
        }
        for (int i = 0; i < k; i++) {
            BigInteger a = uniformRandom(TWO, n.subtract(ONE));
            BigInteger x = a.modPow(d, n);
            if (x.equals(ONE) || x.equals(n.subtract(ONE)))
                    continue;
            int r = 0;
            for (; r < s; r++) {
                x = x.modPow(TWO, n);
                if (x.equals(ONE))
                    return false;
                if (x.equals(n.subtract(ONE)))
                    break;
            }
            if (r == s)
                    return false;
        }
        return true;
    }
    
    private BigInteger uniformRandom(BigInteger bottom, BigInteger top) {
        Random rnd = new Random();
        BigInteger res;
        do {
            res = new BigInteger(top.bitLength(), rnd);
        } while (res.compareTo(bottom) < 0 || res.compareTo(top) > 0);
        return res;
    }

    private BigInteger gcd(BigInteger e, BigInteger z) {
        if (e.equals(ZERO))
            return z;
        else
            return gcd(z.remainder(e), e);
    }

    public Map<String, String> generateKey() {
        BigInteger p, q;
        do {
            p = BigInteger.probablePrime(KEY_SIZE, new Random());
        } while (!isProbablePrime(p, 10));
        do {
            q = BigInteger.probablePrime(KEY_SIZE, new Random());
        } while (!isProbablePrime(q, 10));
        Map<String, String> keys = new HashMap<>();
        BigInteger n, z, d = ZERO, e, i;
        n = p.multiply(q);
        z = p.subtract(ONE).multiply(q.subtract(ONE));
        for (e = TWO; e.compareTo(z) < 0; e = e.add(ONE)) {
            if (gcd(e, z).equals(ONE)) {
                break;
            }
        }
        for (i = ZERO; i.compareTo(new BigInteger("1000000000")) <= 0; i = i.add(ONE)) {
            BigInteger x = ONE.add(i.multiply(z));
            if (x.remainder(e).equals(ZERO)) {
                d = x.divide(e);
                break;
            }
        }
        String publicKey = "e:" + e.toString() + ",n:" + n.toString();
        String privateKey = "d:" + d.toString() + ",n:" + n.toString();
        keys.put("public_key", stringTextToHexa(publicKey));
        keys.put("private_key", stringTextToHexa(privateKey));
        return keys;
    }

    private String byteArrayToHexString(byte[] in) {
        StringBuilder sb = new StringBuilder();
        for (byte b : in) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }

    private byte[] hexStringToByteArray(String hexString) {
        int length = hexString.length();
        byte[] byteArray = new byte[length / 2];
        for (int i = 0; i < length; i += 2) {
            byteArray[i / 2] = (byte) ((Character.digit(hexString.charAt(i), 16) << 4) + Character.digit(hexString.charAt(i + 1), 16));
        }
        return byteArray;
    }

    private String byteArrayToString(byte[] bytes) {
        return new String(bytes);
    }

    private List<String> keyToValue(String key) {
        key = byteArrayToString(hexStringToByteArray(key));
        List<String> list = new ArrayList<>();
        String[] values = key.split(",");
        list.add(values[0].substring(2));
        list.add(values[1].substring(2));
        return list;
    }

    private String stringTextToHexa(String text) {
        byte[] bytes = text.getBytes();
        return byteArrayToHexString(bytes);
    }

    public String encrypt(String text, String publicKey) {
        byte[] plainText = text.getBytes();
        List<String> values = keyToValue(publicKey);
        BigInteger e = new BigInteger(values.get(0));
        BigInteger n = new BigInteger(values.get(1));
        byte[] result = (new BigInteger(plainText)).modPow(e, n).toByteArray();
        return byteArrayToHexString(result);
    }

    public String decrypt(String hexa, String privateKey) {
        byte[] cipherText = hexStringToByteArray(hexa);
        List<String> values = keyToValue(privateKey);
        BigInteger d = new BigInteger(values.get(0));
        BigInteger n = new BigInteger(values.get(1));
        byte[] result = (new BigInteger(cipherText)).modPow(d, n).toByteArray();
        return byteArrayToString(result);
    }
}
