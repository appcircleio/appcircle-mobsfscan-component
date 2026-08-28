package com.example.studio;

/** Deliberately insecure sample used by the advance mode tests. */
public class MainActivity {

    private static final String SECRET_KEY = "hardcoded_secret_key_1234";

    public String key() {
        return SECRET_KEY;
    }
}
