package net.kasterma.cryptopals.set1;

import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

@Slf4j
class Problem1Test {
    static String in = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    static String out = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

    @Test
    void testGiven() {
        log.info("in.len {}", in.length());
        log.info("out.len {}", out.length());
        byte[] indat = Problem1.fromHex(in);
        String outEnc = Problem1.toBase64(indat);
        assertTrue(outEnc.equals(out));
    }
}