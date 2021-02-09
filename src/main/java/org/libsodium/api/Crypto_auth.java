/*
 * The MIT License
 *
 * Copyright 2019 ITON Solutions.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package org.libsodium.api;

import org.libsodium.jni.Sodium;
import org.libsodium.jni.SodiumException;

import static org.libsodium.jni.SodiumConstants.*;

/**
 *
 * @author ITON Solutions
 */
public class Crypto_auth extends Crypto{

    public static byte[] authenticate(byte[] data, byte[] key) throws SodiumException {
        byte[] cipher = new byte[CRYPTO_AUTH_BYTES];
        exception(Sodium.crypto_auth(cipher, data, data.length, key), "crypto_auth");
        return cipher;
    }
    
    public static boolean verify(byte[] cipher, byte[] data, byte[] key) throws SodiumException {
        exception(Sodium.crypto_auth_verify(cipher, data, data.length, key), "crypto_auth_verify");
        return true;
    }
   
    public static byte[] keygen() throws SodiumException {
        // FIXME: crypto_auth_keygen not implemented in libsodium-jni, falling back to randombytes_buf
        byte[] key = new byte[CRYPTO_AUTH_KEYBYTES];
        Crypto_randombytes.buf(key);
        return key;
    }

    public static byte[] hmacsha256(byte[] message, byte[] key) throws SodiumException {
        byte[] cipher = new byte[CRYPTO_AUTH_HMACSHA256_BYTES];
        exception(Sodium.crypto_auth_hmacsha256(cipher, message, message.length, key), "crypto_auth_hmacsha256");
        return cipher;
    }

    public static byte[] hmacsha256_init(byte[] key) throws SodiumException {
        byte[] state = new byte[CRYPTO_AUTH_HMACSHA256_STATEBYTES];
        exception(Sodium.crypto_auth_hmacsha256_init(state, key, key.length), "crypto_auth_hmacsha256_init");
        return state;
    }

    public static boolean hmacsha256_update(byte[] state, byte[] data) throws SodiumException {
        exception(Sodium.crypto_auth_hmacsha256_update(state, data, data.length), "crypto_auth_hmacsha256_update");
        return true;
    }

    public static byte[] hmacsha256_final(byte[] state) throws SodiumException {
        byte[] cipher = new byte[CRYPTO_AUTH_HMACSHA256_BYTES];
        exception(Sodium.crypto_auth_hmacsha256_final(state, cipher), "crypto_auth_hmacsha256_final");
        return cipher;
    }

    public static boolean hmacsha256_verify(byte[] cipher, byte[] data, byte[] key) throws SodiumException {
        exception(Sodium.crypto_auth_hmacsha256_verify(cipher, data, data.length, key), "crypto_auth_hmacsha256_verify");
        return true;
    }
}
