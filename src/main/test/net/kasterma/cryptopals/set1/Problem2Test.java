package net.kasterma.cryptopals.set1;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class Problem2Test {
    static String in1 = "1c0111001f010100061a024b53535009181c";
    static String in2 = "686974207468652062756c6c277320657965";
    static String out = "746865206b696420646f6e277420706c6179";

    @Test
    void test() {
        assertTrue(out.equals(Problem2.xor(in1, in2)));
    }
}