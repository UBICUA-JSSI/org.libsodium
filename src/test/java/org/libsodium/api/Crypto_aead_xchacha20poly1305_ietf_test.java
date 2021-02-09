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

import java.util.Map;

import org.junit.jupiter.api.Test;
import org.libsodium.jni.NaCl;
import org.libsodium.jni.SodiumException;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.libsodium.jni.SodiumConstants.CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NONCEBYTES;

public class Crypto_aead_xchacha20poly1305_ietf_test {
    
    public Crypto_aead_xchacha20poly1305_ietf_test() {
        NaCl.sodium();
    }
    

    /**
     * Test of crypto_aead_xchacha20poly1305_ietf_encrypt_decrypt_detached method, of class SodiumAPI.
     * @throws SodiumException
     */
    @Test
    public void testCrypto_aead_xchacha20poly1305_ietf_encrypt_decrypt_detached() throws SodiumException {
        
        byte[] nonce = new byte[CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NONCEBYTES];
        Crypto_randombytes.buf(nonce);
        byte[] key = Crypto_aead_xchacha20poly1305_ietf.keygen();
        byte[] data = "Hola caracola".getBytes();
        byte[] add = "Random authenticated additional data".getBytes();

        Map<String, byte[]> result = Crypto_aead_xchacha20poly1305_ietf.encrypt_detached(data, add, nonce, key);
        
        byte[] cipher = result.get("cipher");
        byte[] tag = result.get("tag");

        byte[] decrypted = Crypto_aead_xchacha20poly1305_ietf.decrypt_detached(cipher, tag, add, nonce, key);
        assertArrayEquals(data, decrypted);
    }
        
    
    /**
     * Test of crypto_aead_xchacha20poly1305_encrypt_decrypt method, of class SodiumAPI.
     */
    @Test
    public void testCrypto_aead_xchacha20poly1305_ietf_encrypt_decrypt() throws Exception {
        
        byte[] nonce = new byte[CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NONCEBYTES];
        Crypto_randombytes.buf(nonce);
        byte[] key = Crypto_aead_xchacha20poly1305_ietf.keygen();
        byte[] data = "Hola caracola".getBytes();
        byte[] add = "Random authenticated additional data".getBytes();
        
        byte[] cipher = Crypto_aead_xchacha20poly1305_ietf.encrypt(data, add, nonce, key);
        byte[] decrypted = Crypto_aead_xchacha20poly1305_ietf.decrypt(cipher, add, nonce, key);
        assertArrayEquals(data, decrypted);
    }
    
}
