package com.example.clean;

/** A sample with no insecure patterns, used to verify a clean scan still reports. */
public class Calculator {

    public int add(int first, int second) {
        return first + second;
    }

    public int multiply(int first, int second) {
        return first * second;
    }
}
