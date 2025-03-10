/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */

package com.groupkma.EncryptAndMask.security;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.springframework.stereotype.Component;
/**
 *
 * @author minhp
 */

@Component
public class AES {

    private static final int KEY_SIZE = 128;
    private static final int BLOCK_SIZE = KEY_SIZE / 8;
    private static final int Nb = 4;
    private static final int Nk = KEY_SIZE / 32;
    private static final int Nr = Nk + 6;

    private byte[] Key;
    private byte[][] state;
    private byte[] RoundKey = new byte[240];

    private static final int[] sbox = { 0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7,
            0xAB, 0x76, 0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
            0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15, 0x04, 0xC7,
            0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75, 0x09, 0x83, 0x2C, 0x1A,
            0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84, 0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC,
            0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF, 0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85,
            0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8, 0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6,
            0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2, 0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D,
            0x64, 0x5D, 0x19, 0x73, 0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E,
            0x0B, 0xDB, 0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
            0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08, 0xBA, 0x78,
            0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A, 0x70, 0x3E, 0xB5, 0x66,
            0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E, 0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9,
            0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF, 0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68,
            0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16 };

    private static final int[] rsbox = { 0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3,
            0xD7, 0xFB, 0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
            0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E, 0x08, 0x2E,
            0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25, 0x72, 0xF8, 0xF6, 0x64,
            0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92, 0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED,
            0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84, 0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A,
            0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06, 0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF,
            0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B, 0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE,
            0xF0, 0xB4, 0xE6, 0x73, 0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75,
            0xDF, 0x6E, 0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
            0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4, 0x1F, 0xDD,
            0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F, 0x60, 0x51, 0x7F, 0xA9,
            0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF, 0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A,
            0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61, 0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26,
            0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D };

    private static final int[] Rcon = { 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab,
            0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39,
            0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8,
            0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f,
            0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3,
            0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb };

    public AES(String customKey) {
        state = new byte[4][4];
        if (customKey != null && customKey.length() == BLOCK_SIZE) {
            this.Key = customKey.getBytes(StandardCharsets.UTF_8);
        } else {
            this.Key = generateRandomKey();
        }
    }

    private byte[] generateRandomKey() {
        SecureRandom random = new SecureRandom();
        byte[] key = new byte[BLOCK_SIZE];
        random.nextBytes(key);
        return key;
    }

    private byte getSBoxValue(int num) {
        return (byte) (sbox[num] & 0xff);
    }

    private byte getSBoxInvert(int num) {
        return (byte) (rsbox[num] & 0xff);
    }

    private void KeyExpansion() {
        int i = 0;
        byte[] temp = new byte[4];
        while (i < Nk) {
            System.arraycopy(Key, i * 4, RoundKey, i * 4, 4);
            i++;
        }
        while (i < Nb * (Nr + 1)) {
            System.arraycopy(RoundKey, (i - 1) * 4, temp, 0, 4);
            if (i % Nk == 0) {
                byte k = temp[0];
                temp[0] = getSBoxValue(temp[1] & 0xff);
                temp[1] = getSBoxValue(temp[2] & 0xff);
                temp[2] = getSBoxValue(temp[3] & 0xff);
                temp[3] = getSBoxValue(k & 0xff);
                temp[0] ^= Rcon[i / Nk];
            }
            for (int j = 0; j < 4; j++) {
                RoundKey[i * 4 + j] = (byte) (RoundKey[(i - Nk) * 4 + j] ^ temp[j]);
            }
            i++;
        }
    }

    private void AddRoundKey(int round) {
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                state[j][i] ^= RoundKey[round * Nb * 4 + i * Nb + j];
            }
        }
    }

    private void SubBytes() {
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                state[i][j] = getSBoxValue(state[i][j] & 0xff);
            }
        }
    }

    private void InvSubBytes() {
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                state[i][j] = getSBoxInvert(state[i][j] & 0xff);
            }
        }
    }

    private void ShiftRows() {
        byte temp;
        temp = state[1][0];
        System.arraycopy(state[1], 1, state[1], 0, 3);
        state[1][3] = temp;

        temp = state[2][0];
        state[2][0] = state[2][2];
        state[2][2] = temp;
        temp = state[2][1];
        state[2][1] = state[2][3];
        state[2][3] = temp;

        temp = state[3][0];
        state[3][0] = state[3][3];
        state[3][3] = state[3][2];
        state[3][2] = state[3][1];
        state[3][1] = temp;
    }

    private void InvShiftRow() {
        byte temp;
        temp = state[1][3];
        System.arraycopy(state[1], 0, state[1], 1, 3);
        state[1][0] = temp;

        temp = state[2][0];
        state[2][0] = state[2][2];
        state[2][2] = temp;
        temp = state[2][1];
        state[2][1] = state[2][3];
        state[2][3] = temp;

        temp = state[3][0];
        state[3][0] = state[3][1];
        state[3][1] = state[3][2];
        state[3][2] = state[3][3];
        state[3][3] = temp;
    }

    private byte xtime(byte x) {
        return (byte) (((x & 0xff) << 1) ^ (((x >> 7) & 1) * 0x1b));
    }

    private byte Multiply(byte x, byte y) {
        int ux = x & 0xff, uy = y & 0xff, result = 0;
        for (int i = 0; i < 8; i++) {
            if ((uy & 1) == 1) result ^= ux;
            boolean carry = (ux & 0x80) != 0;
            ux = (ux << 1) & 0xff;
            if (carry) ux ^= 0x1b;
            uy >>= 1;
        }
        return (byte) result;
    }

    private void MixColumns() {
        for (int i = 0; i < 4; i++) {
            byte t = state[0][i];
            byte tmp = (byte) (state[0][i] ^ state[1][i] ^ state[2][i] ^ state[3][i]);
            byte tm = xtime((byte) (state[0][i] ^ state[1][i]));
            state[0][i] ^= tm ^ tmp;
            tm = xtime((byte) (state[1][i] ^ state[2][i]));
            state[1][i] ^= tm ^ tmp;
            tm = xtime((byte) (state[2][i] ^ state[3][i]));
            state[2][i] ^= tm ^ tmp;
            tm = xtime((byte) (state[3][i] ^ t));
            state[3][i] ^= tm ^ tmp;
        }
    }

    private void InvMixColumns() {
        for (int i = 0; i < 4; i++) {
            byte a = state[0][i], b = state[1][i], c = state[2][i], d = state[3][i];
            state[0][i] = (byte) (Multiply(a, (byte) 0x0e) ^ Multiply(b, (byte) 0x0b) ^ Multiply(c, (byte) 0x0d) ^ Multiply(d, (byte) 0x09));
            state[1][i] = (byte) (Multiply(a, (byte) 0x09) ^ Multiply(b, (byte) 0x0e) ^ Multiply(c, (byte) 0x0b) ^ Multiply(d, (byte) 0x0d));
            state[2][i] = (byte) (Multiply(a, (byte) 0x0d) ^ Multiply(b, (byte) 0x09) ^ Multiply(c, (byte) 0x0e) ^ Multiply(d, (byte) 0x0b));
            state[3][i] = (byte) (Multiply(a, (byte) 0x0b) ^ Multiply(b, (byte) 0x0d) ^ Multiply(c, (byte) 0x09) ^ Multiply(d, (byte) 0x0e));
        }
    }

    private byte[] Cipher(byte[] in, byte[] iv) {
        byte[] out = new byte[BLOCK_SIZE];
        byte[] input = xorWithIv(in, iv);
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                state[j][i] = input[i * 4 + j];
            }
        }
        KeyExpansion();
        AddRoundKey(0);
        for (int round = 1; round < Nr; round++) {
            SubBytes();
            ShiftRows();
            MixColumns();
            AddRoundKey(round);
        }
        SubBytes();
        ShiftRows();
        AddRoundKey(Nr);
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                out[i * 4 + j] = state[j][i];
            }
        }
        return out;
    }

    private byte[] DeCipher(byte[] in, byte[] iv) {
        byte[] out = new byte[BLOCK_SIZE];
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                state[j][i] = in[i * 4 + j];
            }
        }
        KeyExpansion();
        AddRoundKey(Nr);
        for (int round = Nr - 1; round > 0; round--) {
            InvShiftRow();
            InvSubBytes();
            AddRoundKey(round);
            InvMixColumns();
        }
        InvShiftRow();
        InvSubBytes();
        AddRoundKey(0);
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                out[i * 4 + j] = state[j][i];
            }
        }
        return removePKCS7Padding(xorWithIv(out, iv));
    }

    private byte[] addPKCS7Padding(byte[] data) {
        int paddingLength = BLOCK_SIZE - (data.length % BLOCK_SIZE);
        byte[] padded = new byte[data.length + paddingLength];
        System.arraycopy(data, 0, padded, 0, data.length);
        Arrays.fill(padded, data.length, padded.length, (byte) paddingLength);
        return padded;
    }

    private byte[] removePKCS7Padding(byte[] padded) {
        int paddingLength = padded[padded.length - 1] & 0xff;
        if (paddingLength <= 0 || paddingLength > BLOCK_SIZE) return padded;
        return Arrays.copyOf(padded, padded.length - paddingLength);
    }

    private byte[] xorWithIv(byte[] in, byte[] iv) {
        byte[] result = new byte[in.length];
        for (int i = 0; i < in.length; i++) {
            result[i] = (byte) (in[i] ^ iv[i % iv.length]);
        }
        return result;
    }

    private List<byte[]> splitIntoBlocks(byte[] input) {
        List<byte[]> blocks = new ArrayList<>();
        for (int i = 0; i < input.length; i += BLOCK_SIZE) {
            int len = Math.min(BLOCK_SIZE, input.length - i);
            byte[] block = new byte[len];
            System.arraycopy(input, i, block, 0, len);
            if (len < BLOCK_SIZE) block = addPKCS7Padding(block);
            blocks.add(block);
        }
        return blocks;
    }

    private byte[] mergeArrays(byte[]... arrays) {
        int totalLength = 0;
        for (byte[] array : arrays) totalLength += array.length;
        byte[] result = new byte[totalLength];
        int offset = 0;
        for (byte[] array : arrays) {
            System.arraycopy(array, 0, result, offset, array.length);
            offset += array.length;
        }
        return result;
    }

    private String byteArrayToHexString(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }

    private byte[] hexStringToByteArray(String hex) {
        byte[] bytes = new byte[hex.length() / 2];
        for (int i = 0; i < hex.length(); i += 2) {
            bytes[i / 2] = (byte) Integer.parseInt(hex.substring(i, i + 2), 16);
        }
        return bytes;
    }

    public String encrypt(String plainText) {
        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[BLOCK_SIZE];
        random.nextBytes(iv);
        byte[] plainBytes = plainText.getBytes(StandardCharsets.UTF_8);
        List<byte[]> blocks = splitIntoBlocks(plainBytes);
        byte[] cipherBytes = iv;
        byte[] previousBlock = iv;
        for (byte[] block : blocks) {
            byte[] encryptedBlock = Cipher(block, previousBlock);
            cipherBytes = mergeArrays(cipherBytes, encryptedBlock);
            previousBlock = encryptedBlock;
        }
        return byteArrayToHexString(cipherBytes);
    }

    public String decrypt(String cipherText) {
        byte[] cipherBytes = hexStringToByteArray(cipherText);
        byte[] iv = Arrays.copyOfRange(cipherBytes, 0, BLOCK_SIZE);
        byte[] data = Arrays.copyOfRange(cipherBytes, BLOCK_SIZE, cipherBytes.length);
        List<byte[]> blocks = splitIntoBlocks(data);
        byte[] plainBytes = new byte[0];
        byte[] previousBlock = iv;
        for (byte[] block : blocks) {
            byte[] decryptedBlock = DeCipher(block, previousBlock);
            plainBytes = mergeArrays(plainBytes, decryptedBlock);
            previousBlock = block;
        }
        return new String(plainBytes, StandardCharsets.UTF_8);
    }

    public byte[] getKey() {
        return Key.clone();
    }

    public static void main(String[] args) {
        AES aes = new AES("MySecretKey12345");
        String plainText = "Hello, World!";
        String encrypted = aes.encrypt(plainText);
        System.out.println("Encrypted: " + encrypted);
        String decrypted = aes.decrypt(encrypted);
        System.out.println("Decrypted: " + decrypted);
    }
}
