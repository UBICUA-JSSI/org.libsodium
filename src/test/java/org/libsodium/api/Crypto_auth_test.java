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

import org.junit.jupiter.api.Test;
import org.libsodium.jni.NaCl;
import org.libsodium.jni.SodiumException;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.libsodium.jni.SodiumConstants.*;

public class Crypto_auth_test {
    
    public Crypto_auth_test() {
        NaCl.sodium();
    }
    
    /**
     * Test of crypto_auth_encrypt_authenticate_verify method, of class Crypto_auth.
     * @throws SodiumException
     */
    @Test
    public void testCrypto_auth_encrypt_authenticate_verify() throws SodiumException {
        
        byte[] key = Crypto_auth.keygen();
        byte[] data = "Hola caracola".getBytes();
        byte[] cipher = Crypto_auth.authenticate(data, key);
        boolean result = Crypto_auth.verify(cipher, data, key);
        assertTrue(result);
    }

    @Test
    public void testCrypto_auth_hmacsha256_verify() throws SodiumException {

        byte[] key = new byte[CRYPTO_AUTH_KEYBYTES];
        byte[] data = "Hola caracola".getBytes();
        byte[] cipher = Crypto_auth.hmacsha256(data, key);
        boolean result = Crypto_auth.hmacsha256_verify(cipher, data, key);
        assertTrue(result);
    }

    @Test
    public void testCrypto_auth_hmacsha256_multipart_verify() throws SodiumException {

        byte[] key = new byte[CRYPTO_AUTH_HMACSHA256_KEYBYTES];

        byte[] data1 = "Arbitrary data to hash".getBytes();
        byte[] data2 = " is longer than expected".getBytes();
        byte[] append = new byte[data1.length + data2.length];
        System.arraycopy(data1, 0, append, 0, data1.length);
        System.arraycopy(data2, 0, append, data1.length, data2.length);

        byte[] state = Crypto_auth.hmacsha256_init(key);
        Crypto_auth.hmacsha256_update(state, data1);
        Crypto_auth.hmacsha256_update(state, data2);
        byte[] cipher = Crypto_auth.hmacsha256_final(state);
        boolean result = Crypto_auth.hmacsha256_verify(cipher, append, key);
        assertTrue(result);
    }
    
}
