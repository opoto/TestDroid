package org.opoto.testdroid;

import android.content.Context;
import android.hardware.Sensor;
import android.hardware.SensorManager;
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
import androidx.biometric.BiometricManager;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.Principal;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

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

        // VARIOUS

        TextView miscTxt = findViewById(R.id.misc_txt);

        SensorManager sensorManager = (SensorManager) getSystemService(Context.SENSOR_SERVICE);
        Sensor sensor = sensorManager.getDefaultSensor(Sensor.TYPE_STEP_COUNTER);
        List<Sensor> sensors = sensorManager.getSensorList(Sensor.TYPE_ALL);
        String SensorTxt = "";
        for (Sensor _sensor: sensors) {
            SensorTxt += _sensor.getName() + "\n";
        }
        final CheckBox stepCounter = findViewById(R.id.step_counter);
        stepCounter.setChecked(sensor != null);
        miscTxt.setText(SensorTxt);

        // ============================== KEYSTORE TESTS


        final CheckBox androidKeystore = findViewById(R.id.android_keystore);
        final CheckBox hardwareBacked = findViewById(R.id.hardware_backed);
        final CheckBox keyAttestation = findViewById(R.id.key_attestation);
        final CheckBox strongbox = findViewById(R.id.strongbox);

        Date now = new Date();
        Date originationEnd = new Date(now.getTime() + 0); // from now
        Date consumptionEnd = new Date(now.getTime() + (1000 * 24 * 365 * 2)); // 2 years

        // Strongbox
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE);
            KeyGenParameterSpec.Builder kps = new KeyGenParameterSpec.Builder(
                    MY_KEY,
                    KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                    .setDigests(KeyProperties.DIGEST_NONE, KeyProperties.DIGEST_SHA256)
                    .setKeyValidityStart(now)
                    .setKeyValidityForOriginationEnd(originationEnd)
                    .setKeyValidityForConsumptionEnd(consumptionEnd);

            kps.setIsStrongBoxBacked(true);
            kpg.initialize(kps.build());
            KeyPair keypair = kpg.generateKeyPair();
            strongbox.setChecked(true);

        } catch (Exception ex) {
            Log.e(LOG_TAG, "StrongBox failed: " + ex.toString());
        }

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
                    .setDigests(KeyProperties.DIGEST_NONE, KeyProperties.DIGEST_SHA256)
                    .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                    .setKeyValidityStart(now)
                    .setKeyValidityForOriginationEnd(originationEnd)
                    .setKeyValidityForConsumptionEnd(consumptionEnd)
                    .setAttestationChallenge("key attestation test".getBytes());

            kpg.initialize(kSpec.build());
            KeyPair keypair = kpg.generateKeyPair();

            KeyFactory factory = KeyFactory.getInstance(keypair.getPrivate().getAlgorithm(), ANDROID_KEYSTORE);
            KeyInfo keyInfo = factory.getKeySpec(keypair.getPrivate(), KeyInfo.class);
            hardwareBacked.setChecked(keyInfo.isInsideSecureHardware());

            Certificate[] certificates = ks.getCertificateChain(MY_KEY);
            Certificate rootCA = certificates[certificates.length - 1];
            byte[] rootSN = ((X509Certificate) rootCA).getSerialNumber().toByteArray();
            Principal rootSub = ((X509Certificate) rootCA).getSubjectDN();
            if (Arrays.equals(rootSN, GOOGLE_ROOT_CA_SN)) {
                keyAttestation.setChecked(true);
            }
            Log.i(LOG_TAG, "Certs: " + certificates.length );
            Log.i(LOG_TAG, "root: SN=" + Arrays.toString(rootSN) + ", subject=" + rootSub.getName());
            Log.i(LOG_TAG, "All checked passed");

            // BIOMETRICS

            final CheckBox bioAvailable = findViewById(R.id.bio_available);
            final CheckBox bioEnrolled = findViewById(R.id.bio_enrolled);
            final CheckBox bioReady = findViewById(R.id.bio_ready);

            BiometricManager biometricManager = BiometricManager.from(this);
            switch (biometricManager.canAuthenticate()) {
                case BiometricManager.BIOMETRIC_SUCCESS:
                    bioAvailable.setChecked(true);
                    bioEnrolled.setChecked(true);
                    bioReady.setChecked(true);
                    break;
                case BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE:
                    break;
                case BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE:
                    bioAvailable.setChecked(true);
                    bioEnrolled.setChecked(true);
                    break;
                case BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED:
                    bioAvailable.setChecked(true);
                    break;
            }

        } catch (Exception e) {
            e.printStackTrace();
            Log.e(LOG_TAG, e.toString());
            miscTxt.setText("ERROR: " + e.toString());
        }

    }

}
