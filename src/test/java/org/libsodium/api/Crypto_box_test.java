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

public class Crypto_box_test {
    
    public Crypto_box_test() {
        NaCl.sodium();
    }
    

    
    /**
     * Test of crypto_box_seal_open methods, of class SodiumAPI.
     * @throws SodiumException
     */
    @Test
    public void testCrypto_box_seal_open() throws SodiumException {
        
        Map<String, byte[]> result = Crypto_box.keypair();
        byte[] pk = result.get("pk");
        byte[] sk = result.get("sk");
        byte[] data = "Hola caracola".getBytes();
        
        byte[] cipher = Crypto_box.seal(data, pk);
        byte[] opened = Crypto_box.seal_open(cipher, pk, sk);
        assertArrayEquals(data, opened);
    }
}
