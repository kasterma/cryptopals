package net.kasterma.cryptopals.set1;

import com.google.common.io.BaseEncoding;

/**
 * Convert hex to base64.
 * The string:
 *    49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d
 * Should produce:
 *    SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t
 *
 * So go ahead and make that happen. You'll need to use this code for the rest
 * of the exercises.
 *
 * Rule: Always operate on raw bytes, never on encoded strings. Only use hex and
 * base64 for pretty-printing.
 *
 * Note: clearly just use BaseEncoding directly where you need this.
 */
class Problem1 {
    /**
     * Decode the given hexadecimal data.
     *
     * @param hexString hexadecimal encoding of the data we are interested in
     * @return byte array containing the data of interest
     */
    static byte[] fromHex(String hexString) {
        return BaseEncoding.base16().lowerCase().decode(hexString);
    }

    /**
     * Encode the given data to a hexadecimal string.
     *
     * @param dat data to encode
     * @return string encoding of the given data
     */
    static String toHex(byte[] dat) {
        return BaseEncoding.base16().encode(dat);
    }

    /**
     * Decode the given base64 encoded data.
     *
     * @param base64String base64 encoding of the data we are interested in
     * @return byte array containing the data of interest
     */
    static byte[] fromBase64(String base64String) {
        return BaseEncoding.base64().decode(base64String);
    }

    /**
     * Encode the given data to a base64 encoded string.
     *
     * @param dat data to encode
     * @return string encoding of the given data
     */
    static String toBase64(byte[] dat) {
        return BaseEncoding.base64().encode(dat);
    }
}