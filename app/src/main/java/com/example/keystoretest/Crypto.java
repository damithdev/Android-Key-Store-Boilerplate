package com.example.keystoretest;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;
import android.util.Log;
import android.widget.Toast;

import java.security.KeyStore;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;

public class Crypto {

    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final String ANDROID_KEY_STORE = "AndroidKeyStore";

    private static final int TIMEOUT_SECONDS=60;
    private KeyStore ks;

    public Crypto() {
        try {
            ks=KeyStore.getInstance(ANDROID_KEY_STORE);
            ks.load(null);
        }
        catch (Exception e) {
            Log.e(getClass().getSimpleName(), "Exception initializing keystore", e);
        }
    }

    private void createKeyForTimeout(String KEY_NAME) throws Exception {
        KeyStore.Entry entry=ks.getEntry(KEY_NAME, null);

        if (entry==null) {
            KeyGenParameterSpec spec=
                    new KeyGenParameterSpec.Builder(KEY_NAME,
                            KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                            .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                            .setUserAuthenticationRequired(true)
                            .setUserAuthenticationValidityDurationSeconds(TIMEOUT_SECONDS)
                            .build();

            KeyGenerator keygen=
                    KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEY_STORE);

            keygen.init(spec);
            keygen.generateKey();
        }
    }

    public String isInsideSecureHardware(String KEY_NAME) {
        try {
            createKeyForTimeout(KEY_NAME);
        }
        catch (Exception e) {
            Log.e(getClass().getSimpleName(), "Exception creating key", e);
            return e.getCause().getMessage();
        }

        try {
            SecretKey key=(SecretKey)ks.getKey(KEY_NAME, null);
            KeyInfo info=
                    (KeyInfo) SecretKeyFactory.getInstance(key.getAlgorithm(), ANDROID_KEY_STORE)
                            .getKeySpec(key, KeyInfo.class);

            if (info.isInsideSecureHardware()) {
                Log.i("SH","Key is inside secure hardware");
                return "Key is inside secure hardware";
            }
            else {
                Log.i("SH","Key is only secured by software");
                return "Key is only secured by software";

            }
        }
        catch (Exception e) {
            Log.e(getClass().getSimpleName(), "Exception getting key info", e);
            return e.getCause().getMessage();
        }
    }
}
