package io.easycipher;

import androidx.appcompat.app.AppCompatActivity;

import android.annotation.SuppressLint;
import android.os.AsyncTask;
import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;

import io.easycipher.test.AESTest;
import io.easycipher.test.EccTest;
import io.easycipher.test.EfficiencyTest;
import io.easycipher.test.RSATest;
import io.easycipher.test.SHATest;


public class MainActivity extends AppCompatActivity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        AsyncTask.SERIAL_EXECUTOR.execute(this::test);

        AsyncTask.SERIAL_EXECUTOR.execute(EfficiencyTest::compareTime);
    }

    @SuppressLint("SetTextI18n")
    private void test() {
        try {
            TextView tv = this.findViewById(R.id.test_tv);

            StringBuilder builder = new StringBuilder();
            boolean aes = AESTest.test();
            builder.append("aes ").append((aes ? "success" : "failed")).append('\n');
            tv.post(() -> tv.setText(builder.toString()));

            boolean sha256 = SHATest.testSHA256();
            builder.append("sha ").append((sha256 ? "success" : "failed")).append('\n');
            tv.post(() -> tv.setText(builder.toString()));

            boolean hmac = SHATest.testHmacSHA256();
            builder.append("hmac ").append((hmac ? "success" : "failed")).append('\n');
            tv.post(() -> tv.setText(builder.toString()));

            boolean ecc = EccTest.test();
            builder.append("ecc ").append((ecc ? "success" : "failed")).append('\n');
            tv.post(() -> tv.setText(builder.toString()));

            boolean rsa = RSATest.testCrypt();
            builder.append("rsa ").append((rsa ? "success" : "failed")).append('\n');
            tv.post(() -> tv.setText(builder.toString()));
        } catch (Exception e) {
            Log.e("MyTag", e.getMessage(), e);
        }
    }
}
