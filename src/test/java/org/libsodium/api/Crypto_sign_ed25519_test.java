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
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.libsodium.jni.SodiumConstants.CRYPTO_SIGN_PUBLICKEYBYTES;

/**
 *
 * @author Andrei
 */
public class Crypto_sign_ed25519_test {
    
    public Crypto_sign_ed25519_test() {
        NaCl.sodium();
    }

    /**
     * Test of crypto_box_seal_open methods, of class SodiumAPI.
     * @throws SodiumException
     */
    @Test
    public void testCrypto_sign_ed25519_sign_verify() throws SodiumException {
        
        Map<String, byte[]> result = Crypto_sign_ed25519.keypair();
        byte[] pk = result.get("pk");
        byte[] sk = result.get("sk");
        byte[] data = "Hola caracola".getBytes();
        
        byte[] sign = Crypto_sign_ed25519.sign(data, sk);
        boolean verified = Crypto_sign_ed25519.verify(data, sign, pk);
        assertTrue(verified);
    }
    
    /**
     * Test of crypto_box_seal_open methods, of class SodiumAPI.
     * @throws SodiumException
     */
    @Test
    public void testCrypto_sign_ed25519_detached_verify() throws SodiumException {
        
        Map<String, byte[]> result = Crypto_sign_ed25519.keypair();
        byte[] pk = result.get("pk");
        byte[] sk = result.get("sk");
        byte[] data = "Hola caracola".getBytes();
        
        byte[] sign = Crypto_sign_ed25519.detached(data, sk);
        boolean verified = Crypto_sign_ed25519.verify_detached(data, sign, pk);
        assertTrue(verified);
    }

    @Test
    public void testCrypto_sign_ed25519_sk_to_pk() throws SodiumException {

        Map<String, byte[]> pair = Crypto_sign_ed25519.keypair();
        byte[] pk = pair.get("pk");
        byte[] sk = pair.get("sk");

        byte[] result = new byte[CRYPTO_SIGN_PUBLICKEYBYTES];
        System.arraycopy(sk, sk.length - result.length, result, 0, result.length);
        assertArrayEquals(result, pk);

        result = Crypto_sign_ed25519.sk_to_pk(sk);
        assertArrayEquals(result, pk);
    }
}
