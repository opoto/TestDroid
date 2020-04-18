package org.opoto.testdroid;

import android.os.Build;
import android.os.Bundle;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;
import android.util.Log;
import android.widget.CheckBox;
import android.widget.TextView;

import androidx.annotation.RequiresApi;
import androidx.appcompat.app.AppCompatActivity;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import javax.security.auth.x500.X500Principal;

public class MainActivity extends AppCompatActivity {

    private static final String ANDROID_KEYSTORE = "AndroidKeyStore";
    private static final String MY_KEY = "MyKey";
    private static final byte[] GOOGLE_ROOT_CA_SN = new byte[]{
            (byte) 0xe8, (byte) 0xfa, (byte) 0x19, (byte) 0x63,
            (byte) 0x14, (byte) 0xd2, (byte) 0xfa, (byte) 0x18
    };
    private static final String LOG_TAG = MainActivity.class.getSimpleName();

    @RequiresApi(api = Build.VERSION_CODES.P)
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        // ============================= DEVICE INFO

        String s = "";
        s += "Device: " + Build.MANUFACTURER + " " + Build.MODEL + "\n";
        s += "OS Version: " + Build.VERSION.BASE_OS + " " + Build.VERSION.CODENAME + " " + Build.VERSION.RELEASE +
                " (API " + Build.VERSION.SDK_INT + ")\n";
        s += "Board: " + Build.BOARD + "\n";
        s += "Hardware: " + Build.HARDWARE + "\n";
        s += "ABIs: " + Arrays.toString(Build.SUPPORTED_ABIS);

        TextView deviceInfo = findViewById(R.id.device_info);
        deviceInfo.setText(s);

        // ============================== KEYSTORE TESTS

        final CheckBox androidKeystore = findViewById(R.id.android_keystore);
        final CheckBox hardwareBacked = findViewById(R.id.hardware_backed);
        final CheckBox keyAttestation = findViewById(R.id.key_attestation);
        final CheckBox strongbox = findViewById(R.id.strongbox);

        androidKeystore.setChecked(false);
        hardwareBacked.setChecked(false);
        keyAttestation.setChecked(false);
        strongbox.setChecked(false);

        try {

            KeyStore ks = KeyStore.getInstance(ANDROID_KEYSTORE);
            ks.load(null);
            androidKeystore.setChecked(true);

            KeyPairGenerator kpg = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_RSA, ANDROID_KEYSTORE);
            KeyGenParameterSpec.Builder kSpec = new KeyGenParameterSpec.Builder(
                    MY_KEY,
                    KeyProperties.PURPOSE_SIGN)
                    .setKeySize(2048)
                    .setCertificateSubject(new X500Principal("CN=unused"))
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1);

            try {
                kSpec.setIsStrongBoxBacked(true);
                strongbox.setChecked(true);
            } catch (Throwable err) {
                //
            }

            kpg.initialize(kSpec.build());
            KeyPair keypair = kpg.generateKeyPair();

            KeyFactory factory = KeyFactory.getInstance(keypair.getPrivate().getAlgorithm(), ANDROID_KEYSTORE);
            KeyInfo keyInfo = factory.getKeySpec(keypair.getPrivate(), KeyInfo.class);
            hardwareBacked.setChecked(keyInfo.isInsideSecureHardware());

            Certificate[] certificates = ks.getCertificateChain(MY_KEY);
            Certificate rootCA = certificates[certificates.length - 1];
            byte[] rootSN = ((X509Certificate) rootCA).getSerialNumber().toByteArray();
            if (Arrays.equals(rootSN, GOOGLE_ROOT_CA_SN)) {
                keyAttestation.setChecked(true);
            }
            Log.i(LOG_TAG, "Certs: " + certificates.length );
            Log.i(this.getClass().getSimpleName(), "root=" + Arrays.toString(rootSN));
            Log.i(this.getClass().getSimpleName(), "All checked passed");

        } catch (Exception e) {
            e.printStackTrace();
        }

    }
}
