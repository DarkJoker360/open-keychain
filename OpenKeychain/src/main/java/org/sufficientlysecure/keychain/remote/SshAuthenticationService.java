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

package org.sufficientlysecure.keychain.remote;


import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;

import android.app.PendingIntent;
import android.app.Service;
import android.content.Intent;
import android.os.IBinder;

import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.openintents.openpgp.OpenPgpError;
import org.openintents.openpgp.util.OpenPgpApi;
import org.openintents.ssh.authentication.ISshAuthenticationService;
import org.openintents.ssh.authentication.SshAuthenticationApi;
import org.openintents.ssh.authentication.SshAuthenticationApiError;
import org.openintents.ssh.authentication.response.KeySelectionResponse;
import org.openintents.ssh.authentication.response.PublicKeyResponse;
import org.openintents.ssh.authentication.response.SigningResponse;
import org.openintents.ssh.authentication.response.SshPublicKeyResponse;
import org.sufficientlysecure.keychain.Constants;
import org.sufficientlysecure.keychain.daos.ApiAppDao;
import org.sufficientlysecure.keychain.daos.KeyRepository;
import org.sufficientlysecure.keychain.daos.KeyRepository.NotFoundException;
import org.sufficientlysecure.keychain.model.UnifiedKeyInfo;
import org.sufficientlysecure.keychain.operations.results.OperationResult.LogEntryParcel;
import org.sufficientlysecure.keychain.pgp.CanonicalizedPublicKey;
import org.sufficientlysecure.keychain.pgp.SshPublicKey;
import org.sufficientlysecure.keychain.pgp.exception.PgpGeneralException;
import org.sufficientlysecure.keychain.pgp.exception.PgpKeyNotFoundException;
import org.sufficientlysecure.keychain.service.input.CryptoInputParcel;
import org.sufficientlysecure.keychain.service.input.RequiredInputParcel;
import org.sufficientlysecure.keychain.ssh.AuthenticationData;
import org.sufficientlysecure.keychain.ssh.AuthenticationOperation;
import org.sufficientlysecure.keychain.ssh.AuthenticationParcel;
import org.sufficientlysecure.keychain.ssh.AuthenticationResult;
import org.sufficientlysecure.keychain.ssh.signature.SshSignatureConverter;
import timber.log.Timber;


public class SshAuthenticationService extends Service {
    private ApiPermissionHelper mApiPermissionHelper;
    private KeyRepository mKeyRepository;
    private ApiAppDao mApiAppDao;
    private ApiPendingIntentFactory mApiPendingIntentFactory;

    private static final List<Integer> SUPPORTED_VERSIONS = Collections.unmodifiableList(Collections.singletonList(1));
    private static final int INVALID_API_VERSION = -1;

    private static final int HASHALGORITHM_NONE = SshAuthenticationApiError.INVALID_HASH_ALGORITHM;

    @Override
    public void onCreate() {
        super.onCreate();
        mApiPermissionHelper = new ApiPermissionHelper(this, ApiAppDao.getInstance(this));
        mKeyRepository = KeyRepository.create(this);
        mApiAppDao = ApiAppDao.getInstance(this);

        mApiPendingIntentFactory = new ApiPendingIntentFactory(getBaseContext());
    }

    private final ISshAuthenticationService.Stub mSSHAgent = new ISshAuthenticationService.Stub() {
        @Override
        public Intent execute(Intent intent) {
            return checkIntent(intent);
        }

    };

    @Override
    public IBinder onBind(Intent intent) {
        return mSSHAgent;
    }

    private Intent checkIntent(Intent intent) {
        android.util.Log.d("SSH_AUTH_SVC", "checkIntent called, action: " + (intent != null ? intent.getAction() : "null"));
        Intent errorResult = checkRequirements(intent);
        if (errorResult == null) {
            android.util.Log.d("SSH_AUTH_SVC", "checkRequirements passed, calling executeInternal");
            return executeInternal(intent);
        } else {
            android.util.Log.e("SSH_AUTH_SVC", "checkRequirements failed, returning error");
            return errorResult;
        }
    }

    private Intent executeInternal(Intent intent) {
        android.util.Log.d("SSH_AUTH_SVC", "executeInternal called, action: " + intent.getAction());
        switch (intent.getAction()) {
            case SshAuthenticationApi.ACTION_SIGN:
                android.util.Log.d("SSH_AUTH_SVC", "ACTION_SIGN - calling authenticate");
                return authenticate(intent);
            case SshAuthenticationApi.ACTION_SELECT_KEY:
                return getAuthenticationKey(intent);
            case SshAuthenticationApi.ACTION_GET_PUBLIC_KEY:
                return getAuthenticationPublicKey(intent, false);
            case SshAuthenticationApi.ACTION_GET_SSH_PUBLIC_KEY:
                return getAuthenticationPublicKey(intent, true);
            default:
                return createErrorResult(SshAuthenticationApiError.UNKNOWN_ACTION, "Unknown action");
        }
    }

    private Intent authenticate(Intent data) {
        android.util.Log.d("SSH_AUTH_SVC", "=== AUTHENTICATE CALLED ===");
        try {
            Intent errorIntent = checkForKeyId(data);
            if (errorIntent != null) {
                android.util.Log.e("SSH_AUTH_SVC", "checkForKeyId returned error");
                return errorIntent;
            }

            // keyid == masterkeyid -> authkeyid
            // keyId is the pgp master keyId, the keyId used will be the first authentication
            // key in the keyring designated by the master keyId
            String keyIdString = data.getStringExtra(SshAuthenticationApi.EXTRA_KEY_ID);
            android.util.Log.d("SSH_AUTH_SVC", "Key ID string: " + keyIdString);
            long masterKeyId = Long.valueOf(keyIdString);
            android.util.Log.d("SSH_AUTH_SVC", "Master key ID: " + masterKeyId);

        int hashAlgorithmTag = getHashAlgorithm(data);
        if (hashAlgorithmTag == HASHALGORITHM_NONE) {
            return createErrorResult(SshAuthenticationApiError.GENERIC_ERROR, "No valid hash algorithm!");
        }

        byte[] challenge = data.getByteArrayExtra(SshAuthenticationApi.EXTRA_CHALLENGE);
        if (challenge == null || challenge.length == 0) {
            return createErrorResult(SshAuthenticationApiError.GENERIC_ERROR, "No challenge given");
        }

        // carries the metadata necessary for authentication
        AuthenticationData.Builder authData = AuthenticationData.builder();
        authData.setAuthenticationMasterKeyId(masterKeyId);

        long authSubKeyId;
        int authSubKeyAlgorithm;
        String authSubKeyCurveOid = null;
        try {
            // get first usable subkey capable of authentication
            authSubKeyId = mKeyRepository.getEffectiveAuthenticationKeyId(masterKeyId);
            // needed for encoding the resulting signature
            authSubKeyAlgorithm = getPublicKey(masterKeyId).getAlgorithm();
            if (authSubKeyAlgorithm == PublicKeyAlgorithmTags.ECDSA) {
                authSubKeyCurveOid = getPublicKey(masterKeyId).getCurveOid();
            }
        } catch (NotFoundException e) {
            return createExceptionErrorResult(SshAuthenticationApiError.NO_SUCH_KEY,
                    "Key for master key id not found", e);
        }

        authData.setAuthenticationSubKeyId(authSubKeyId);

        // When OpenKeychain calls its own SSH authentication service, allow access to all keys
        // For external callers, check the allowed keys from the database
        String callingPackage = mApiPermissionHelper.getCurrentCallingPackage();
        android.util.Log.d("SSH_AUTH_SVC", "Calling package: " + callingPackage);
        if (callingPackage != null && callingPackage.equals(getPackageName())) {
            android.util.Log.d("SSH_AUTH_SVC", "Internal call from OpenKeychain, allowing all keys");
            // Internal call - don't set allowed keys (leaving it null allows all keys)
            // Don't call setAllowedAuthenticationKeyIds at all - the default null value means "allow all"
        } else {
            android.util.Log.d("SSH_AUTH_SVC", "External call, checking allowed keys");
            authData.setAllowedAuthenticationKeyIds(getAllowedKeyIds());
        }

        authData.setHashAlgorithm(hashAlgorithmTag);

        CryptoInputParcel inputParcel = CryptoInputParcelCacheService.getCryptoInputParcel(this, data);
        if (inputParcel == null) {
            // fresh request, assign UUID
            inputParcel = CryptoInputParcel.createCryptoInputParcel(new Date());
        }

        AuthenticationParcel authParcel = AuthenticationParcel
                .createAuthenticationParcel(authData.build(), challenge);

        // execute authentication operation!
        android.util.Log.d("SSH_AUTH_SVC", "Executing authentication operation");
        AuthenticationOperation authOperation = new AuthenticationOperation(this, mKeyRepository);
        AuthenticationResult authResult = authOperation.execute(authData.build(), inputParcel, authParcel);

        android.util.Log.d("SSH_AUTH_SVC", "Authentication result - pending: " + authResult.isPending() + ", success: " + authResult.success());
        if (authResult.isPending()) {
            android.util.Log.d("SSH_AUTH_SVC", "Authentication requires user interaction");
            RequiredInputParcel requiredInput = authResult.getRequiredInputParcel();
            android.util.Log.d("SSH_AUTH_SVC", "Required input type: " + (requiredInput != null ? requiredInput.mType : "null"));
            PendingIntent pi = mApiPendingIntentFactory.requiredInputPi(data, requiredInput,
                    authResult.mCryptoInputParcel);
            android.util.Log.d("SSH_AUTH_SVC", "Created pending intent, returning");
            // return PendingIntent to be executed by client
            return packagePendingIntent(pi);
        } else if (authResult.success()) {
            android.util.Log.d("SSH_AUTH_SVC", "Authentication successful, converting signature");
            byte[] rawSignature = authResult.getSignature();
            byte[] sshSignature;
            try {
                switch (authSubKeyAlgorithm) {
                    case PublicKeyAlgorithmTags.EDDSA:
                        sshSignature = SshSignatureConverter.getSshSignatureEdDsa(rawSignature);
                        break;
                    case PublicKeyAlgorithmTags.RSA_SIGN:
                    case PublicKeyAlgorithmTags.RSA_GENERAL:
                        sshSignature = SshSignatureConverter.getSshSignatureRsa(rawSignature, hashAlgorithmTag);
                        break;
                    case PublicKeyAlgorithmTags.ECDSA:
                        sshSignature = SshSignatureConverter.getSshSignatureEcDsa(rawSignature, authSubKeyCurveOid);
                        break;
                    case PublicKeyAlgorithmTags.DSA:
                        sshSignature = SshSignatureConverter.getSshSignatureDsa(rawSignature);
                        break;
                    default:
                        throw new NoSuchAlgorithmException("Unknown algorithm");
                }
            } catch (NoSuchAlgorithmException e) {
                android.util.Log.e("SSH_AUTH_SVC", "Error converting signature", e);
                return createExceptionErrorResult(SshAuthenticationApiError.INTERNAL_ERROR,
                        "Error converting signature", e);
            }
            android.util.Log.d("SSH_AUTH_SVC", "Returning SigningResponse with " + sshSignature.length + " byte signature");
            Intent result = new SigningResponse(sshSignature).toIntent();
            android.util.Log.d("SSH_AUTH_SVC", "SigningResponse intent result code: " + result.getIntExtra(SshAuthenticationApi.EXTRA_RESULT_CODE, -1));
            return result;
        } else {
            android.util.Log.e("SSH_AUTH_SVC", "Authentication failed");
            LogEntryParcel errorMsg = authResult.getLog().getLast();
            android.util.Log.e("SSH_AUTH_SVC", "Error log type: " + (errorMsg != null ? errorMsg.mType : "null"));
            android.util.Log.e("SSH_AUTH_SVC", "Error message: " + (errorMsg != null ? getString(errorMsg.mType.getMsgId()) : "null"));

            // Log all entries in the operation log to understand what went wrong
            for (LogEntryParcel entry : authResult.getLog().toList()) {
                android.util.Log.d("SSH_AUTH_SVC", "Log entry: " + entry.mType + " - " + getString(entry.mType.getMsgId()));
            }

            return createErrorResult(SshAuthenticationApiError.INTERNAL_ERROR, getString(errorMsg.mType.getMsgId()));
        }
        } catch (Exception e) {
            android.util.Log.e("SSH_AUTH_SVC", "Exception in authenticate: " + e.getClass().getName() + ": " + e.getMessage(), e);
            return createErrorResult(SshAuthenticationApiError.INTERNAL_ERROR, "Exception: " + e.getMessage());
        }
    }

    private Intent checkForKeyId(Intent data) {
        long authMasterKeyId = getKeyId(data);
        if (authMasterKeyId == Constants.key.none) {
            return createErrorResult(SshAuthenticationApiError.NO_KEY_ID,
                    "No key id in request");
        }
        return null;
    }

    private long getKeyId(Intent data) {
        String keyIdString = data.getStringExtra(SshAuthenticationApi.EXTRA_KEY_ID);
        long authMasterKeyId = Constants.key.none;
        if (keyIdString != null) {
            try {
                authMasterKeyId = Long.valueOf(keyIdString);
            } catch (NumberFormatException e) {
                return Constants.key.none;
            }
        }
        return authMasterKeyId;
    }

    private int getHashAlgorithm(Intent data) {
        int hashAlgorithm = data.getIntExtra(SshAuthenticationApi.EXTRA_HASH_ALGORITHM, HASHALGORITHM_NONE);

        switch (hashAlgorithm) {
            case SshAuthenticationApi.SHA1:
                return HashAlgorithmTags.SHA1;
            case SshAuthenticationApi.RIPEMD160:
                return HashAlgorithmTags.RIPEMD160;
            case SshAuthenticationApi.SHA224:
                return HashAlgorithmTags.SHA224;
            case SshAuthenticationApi.SHA256:
                return HashAlgorithmTags.SHA256;
            case SshAuthenticationApi.SHA384:
                return HashAlgorithmTags.SHA384;
            case SshAuthenticationApi.SHA512:
                return HashAlgorithmTags.SHA512;
            default:
                return HASHALGORITHM_NONE;
        }
    }

    private Intent getAuthenticationKey(Intent data) {
        long masterKeyId = getKeyId(data);
        if (masterKeyId != Constants.key.none) {
            String description;

            try {
                description = getDescription(masterKeyId);
            } catch (NotFoundException e) {
                return createExceptionErrorResult(SshAuthenticationApiError.NO_SUCH_KEY,
                        "Could not create description", e);
            }

            return new KeySelectionResponse(String.valueOf(masterKeyId), description).toIntent();
        } else {
            return redirectToKeySelection(data);
        }
    }

    private Intent redirectToKeySelection(Intent data) {
        String currentPkg = mApiPermissionHelper.getCurrentCallingPackage();
        PendingIntent pi = mApiPendingIntentFactory.createSelectAuthenticationKeyIdPendingIntent(data, currentPkg);
        return packagePendingIntent(pi);
    }

    private Intent packagePendingIntent(PendingIntent pi) {
        Intent result = new Intent();
        result.putExtra(SshAuthenticationApi.EXTRA_RESULT_CODE,
                SshAuthenticationApi.RESULT_CODE_USER_INTERACTION_REQUIRED);
        result.putExtra(SshAuthenticationApi.EXTRA_PENDING_INTENT, pi);
        return result;
    }

    private Intent getAuthenticationPublicKey(Intent data, boolean asSshKey) {
        long masterKeyId = getKeyId(data);
        if (masterKeyId != Constants.key.none) {
            try {
                if (asSshKey) {
                    return getSSHPublicKey(masterKeyId);
                } else {
                    return getX509PublicKey(masterKeyId);
                }
            } catch (KeyRepository.NotFoundException e) {
                return createExceptionErrorResult(SshAuthenticationApiError.NO_SUCH_KEY,
                        "Key for master key id not found", e);
            } catch (PgpKeyNotFoundException e) {
                return createExceptionErrorResult(SshAuthenticationApiError.NO_AUTH_KEY,
                        "Authentication key for master key id not found in keychain", e);
            } catch (NoSuchAlgorithmException e) {
                return createExceptionErrorResult(SshAuthenticationApiError.INVALID_ALGORITHM,
                        "Algorithm not supported", e);
            }
        } else {
            return createErrorResult(SshAuthenticationApiError.NO_KEY_ID,
                    "No key id in request");
        }
    }

    private Intent getX509PublicKey(long masterKeyId) throws KeyRepository.NotFoundException, PgpKeyNotFoundException, NoSuchAlgorithmException {
        byte[] encodedPublicKey;
        int algorithm;

        PublicKey publicKey;
        try {
            publicKey = getPublicKey(masterKeyId).getJcaPublicKey();
        } catch (PgpGeneralException e) { // this should probably never happen
            return createExceptionErrorResult(SshAuthenticationApiError.GENERIC_ERROR,
                    "Error converting public key", e);
        }

        encodedPublicKey = publicKey.getEncoded();
        algorithm = translateAlgorithm(publicKey.getAlgorithm());

        return new PublicKeyResponse(encodedPublicKey, algorithm).toIntent();
    }

    private int translateAlgorithm(String algorithm) throws NoSuchAlgorithmException {
        switch (algorithm) {
            case "RSA":
                return SshAuthenticationApi.RSA;
            case "ECDSA":
                return SshAuthenticationApi.ECDSA;
            case "EdDSA":
                return SshAuthenticationApi.EDDSA;
            case "DSA":
                return SshAuthenticationApi.DSA;
            default:
                throw new NoSuchAlgorithmException("Error matching key algorithm to API supported algorithm: "
                        + algorithm);
        }
    }

    private Intent getSSHPublicKey(long masterKeyId) throws KeyRepository.NotFoundException {
        CanonicalizedPublicKey publicKey = getPublicKey(masterKeyId);

        SshPublicKey sshPublicKey = new SshPublicKey(publicKey);
        String sshPublicKeyBlob;
        try {
            sshPublicKeyBlob = sshPublicKey.getEncodedKey();
        } catch (PgpGeneralException | NoSuchAlgorithmException e) {
            return createExceptionErrorResult(SshAuthenticationApiError.GENERIC_ERROR,
                    "Error converting public key to SSH format", e);
        }

        return new SshPublicKeyResponse(sshPublicKeyBlob).toIntent();
    }

    private CanonicalizedPublicKey getPublicKey(long masterKeyId) throws NotFoundException {
        KeyRepository keyRepository = KeyRepository.create(getApplicationContext());
        long authKeyId = keyRepository.getEffectiveAuthenticationKeyId(masterKeyId);
        return keyRepository.getCanonicalizedPublicKeyRing(masterKeyId).getPublicKey(authKeyId);
    }

    private String getDescription(long masterKeyId) throws NotFoundException {
        UnifiedKeyInfo unifiedKeyInfo = mKeyRepository.getUnifiedKeyInfo(masterKeyId);

        String description = "";
        long authSubKeyId = mKeyRepository.getEffectiveAuthenticationKeyId(masterKeyId);
        description += unifiedKeyInfo.user_id();
        description += " (" + Long.toHexString(authSubKeyId) + ")";

        return description;
    }

    private HashSet<Long> getAllowedKeyIds() {
        String currentPkg = mApiPermissionHelper.getCurrentCallingPackage();
        return mApiAppDao.getAllowedKeyIdsForApp(currentPkg);
    }

    /**
     * @return null if basic requirements are met
     */
    private Intent checkRequirements(Intent data) {
        if (data == null) {
            return createErrorResult(SshAuthenticationApiError.GENERIC_ERROR, "No parameter bundle");
        }

        // check version
        int apiVersion = data.getIntExtra(SshAuthenticationApi.EXTRA_API_VERSION, INVALID_API_VERSION);
        if (!SUPPORTED_VERSIONS.contains(apiVersion)) {
            String errorMsg = "Incompatible API versions:\n"
                    + "used : " + data.getIntExtra(SshAuthenticationApi.EXTRA_API_VERSION, INVALID_API_VERSION) + "\n"
                    + "supported : " + SUPPORTED_VERSIONS;

            return createErrorResult(SshAuthenticationApiError.INCOMPATIBLE_API_VERSIONS, errorMsg);
        }

        // check if caller is allowed to access OpenKeychain
        Intent result = mApiPermissionHelper.isAllowedOrReturnIntent(data);
        if (result != null) {
            // Convert OpenPGP API result codes to SSH API result codes
            int openPgpResultCode = result.getIntExtra(OpenPgpApi.RESULT_CODE, OpenPgpApi.RESULT_CODE_ERROR);

            if (openPgpResultCode == OpenPgpApi.RESULT_CODE_USER_INTERACTION_REQUIRED) {
                // Convert to SSH API format
                PendingIntent pendingIntent = result.getParcelableExtra(OpenPgpApi.RESULT_INTENT);
                Intent sshResult = new Intent();
                sshResult.putExtra(SshAuthenticationApi.EXTRA_RESULT_CODE, SshAuthenticationApi.RESULT_CODE_USER_INTERACTION_REQUIRED);
                sshResult.putExtra(SshAuthenticationApi.EXTRA_PENDING_INTENT, pendingIntent);
                return sshResult;
            } else {
                // Convert error to SSH API format
                OpenPgpError error = result.getParcelableExtra(OpenPgpApi.RESULT_ERROR);
                String errorMessage = error != null ? error.getMessage() : "Permission denied";
                return createErrorResult(SshAuthenticationApiError.GENERIC_ERROR, errorMessage);
            }
        }

        return null;
    }

    private Intent createErrorResult(int errorCode, String errorMessage) {
        Timber.e(errorMessage);
        Intent result = new Intent();
        result.putExtra(SshAuthenticationApi.EXTRA_ERROR, new SshAuthenticationApiError(errorCode, errorMessage));
        result.putExtra(SshAuthenticationApi.EXTRA_RESULT_CODE, SshAuthenticationApi.RESULT_CODE_ERROR);
        return result;
    }

    private Intent createExceptionErrorResult(int errorCode, String errorMessage, Exception e) {
        String message = errorMessage + " : " + e.getMessage();
        return createErrorResult(errorCode, message);
    }

}
