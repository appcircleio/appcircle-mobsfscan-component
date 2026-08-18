package com.example.insecure;

/** Covers inline suppression, the key below must not be reported. */
public class SuppressedCode {
    private static final String IGNORED_KEY = "another_secret_key_5678"; // mobsf-ignore: hardcoded_secret, hardcoded_api_key
}
