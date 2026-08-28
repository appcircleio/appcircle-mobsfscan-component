package com.example.insecure;

import android.webkit.WebView;
import java.security.MessageDigest;
import javax.crypto.Cipher;

/** Deliberately insecure Android sample used by the mobsfscan component tests. */
public class InsecureCode {

    private static final String SECRET_KEY = "hardcoded_secret_key_1234";
    private static final String password = "P@ssw0rd123";

    public void configure(WebView webView) {
        webView.getSettings().setJavaScriptEnabled(true);
        webView.getSettings().setAllowFileAccess(true);
    }

    public byte[] weakHash(String data) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("MD5");
        return digest.digest(data.getBytes());
    }

    public Cipher weakCipher() throws Exception {
        return Cipher.getInstance("DES/ECB/PKCS5Padding");
    }
}
