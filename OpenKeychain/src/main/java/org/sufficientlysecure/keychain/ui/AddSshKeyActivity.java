/*
 * Copyright (C) 2017 Schürmann & Breitmoser GbR
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package org.sufficientlysecure.keychain.ui;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.text.TextUtils;
import android.view.MenuItem;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.Toolbar;

import org.sufficientlysecure.keychain.R;
import org.sufficientlysecure.keychain.ssh.SshKeyInfo;
import org.sufficientlysecure.keychain.ssh.utils.SshKeyParser;
import org.sufficientlysecure.keychain.ui.base.BaseActivity;

public class AddSshKeyActivity extends BaseActivity {

    private EditText keyNameEdit;
    private EditText publicKeyEdit;
    private EditText privateKeyEdit;
    private Button btnSave;
    private Button btnCancel;

    @Override
    protected void initLayout() {
        setContentView(R.layout.add_ssh_key_activity);
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        mToolbar.setTitle(R.string.title_add_ssh_key);
        if (getSupportActionBar() != null) {
            getSupportActionBar().setDisplayHomeAsUpEnabled(true);
        }

        initializeViews();
        setupClickListeners();
    }

    private void initializeViews() {
        keyNameEdit = findViewById(R.id.ssh_key_name_edit);
        publicKeyEdit = findViewById(R.id.ssh_public_key_edit);
        privateKeyEdit = findViewById(R.id.ssh_private_key_edit);
        btnSave = findViewById(R.id.btn_save_ssh_key);
        btnCancel = findViewById(R.id.btn_cancel_ssh_key);
    }

    private void setupClickListeners() {
        btnSave.setOnClickListener(v -> saveSshKey());
        btnCancel.setOnClickListener(v -> finish());
    }

    private void saveSshKey() {
        String keyName = keyNameEdit.getText().toString().trim();
        String publicKey = publicKeyEdit.getText().toString().trim();
        String privateKey = privateKeyEdit.getText().toString().trim();

        // Validation
        if (TextUtils.isEmpty(keyName)) {
            keyNameEdit.setError(getString(R.string.error_ssh_key_name_required));
            return;
        }

        if (TextUtils.isEmpty(publicKey)) {
            publicKeyEdit.setError(getString(R.string.error_ssh_public_key_required));
            return;
        }

        try {
            // Parse SSH key to validate format and extract information
            SshKeyParser parser = new SshKeyParser();
            SshKeyParser.ParsedSshKey parsedKey = parser.parsePublicKey(publicKey);

            // Create SshKeyInfo object
            SshKeyInfo sshKeyInfo = new SshKeyInfo(
                    keyName,
                    parsedKey.getType(),
                    parsedKey.getSize(),
                    parsedKey.getFingerprint(),
                    publicKey,
                    privateKey.isEmpty() ? null : privateKey,
                    !privateKey.isEmpty() && parser.isPrivateKeyEncrypted(privateKey)
            );

            // Return result
            Intent resultIntent = new Intent();
            resultIntent.putExtra("ssh_key", sshKeyInfo);
            setResult(Activity.RESULT_OK, resultIntent);
            finish();

        } catch (Exception e) {
            Toast.makeText(this, getString(R.string.error_invalid_ssh_key_format), Toast.LENGTH_LONG).show();
        }
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        if (item.getItemId() == android.R.id.home) {
            finish();
            return true;
        }
        return super.onOptionsItemSelected(item);
    }
}