package net.kasterma.cryptopals.set1;

import com.google.common.io.BaseEncoding;

class Problem2 {
    static String xor(String in1, String in2) {
        byte[] in1b = BaseEncoding.base16().lowerCase().decode(in1);
        byte[] in2b = BaseEncoding.base16().lowerCase().decode(in2);
        return BaseEncoding.base16().lowerCase().encode(xor(in1b, in2b));
    }

    static byte[] xor(byte[] in1, byte[] in2) {
        assert in1.length == in2.length;
        byte[] rv = new byte[in1.length];
        for (int i = 0; i < in1.length; i++) {
            rv[i] = (byte) (in1[i] ^ in2[i]);
        }
        return rv;
    }
}

