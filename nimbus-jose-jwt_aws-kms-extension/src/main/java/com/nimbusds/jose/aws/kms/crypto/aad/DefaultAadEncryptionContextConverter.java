package com.nimbusds.jose.aws.kms.crypto.aad;

import com.google.common.collect.ImmutableMap;
import com.nimbusds.jose.util.Base64URL;

import java.util.Map;

public class DefaultAadEncryptionContextConverter implements AadEncryptionContextConverter {
    /**
     * Key used to store the AAD in the encryption context.
     * Using a prefixed key to avoid collisions with user-defined context.
     *
     * @see <a href="https://docs.aws.amazon.com/kms/latest/developerguide/encrypt_context.html">AWS KMS Encryption Context</a>
     */
    public static final String AAD_CONTEXT_KEY = "_jose_kms_aad";

    /**
     * Maximum length of the base64url-encoded AAD string to ensure it fits within
     * the KMS encryption context limit.
     * The limit for the entire encryption context is 1024 bytes (JSON-encoded).
     * 1000 characters is a safe limit allowing for the key and some user context.
     * <p>
     * todo: check that this is definitely correct
     */
    public static final int MAX_ENCODED_AAD_LENGTH = 1000;

    public ImmutableMap<String, String> aadToEncryptionContext(byte[] aad) {
        if (aad.length == 0) {
            return ImmutableMap.of();
        }

        // Use base64url encoding without padding (standard for JOSE)
        String encoded = Base64URL.encode(aad).toString();

        if (encoded.length() > MAX_ENCODED_AAD_LENGTH) {
            throw new IllegalArgumentException("Encoded AAD length exceeds the maximum supported size for KMS encryption context (" + MAX_ENCODED_AAD_LENGTH + " characters)");
        }

        return ImmutableMap.of(AAD_CONTEXT_KEY, encoded);
    }

    public byte[] encryptionContextToAad(Map<String, String> encryptionContext) {
        String encoded = encryptionContext.get(AAD_CONTEXT_KEY);

        if (encoded == null || encoded.isEmpty()) {
            return new byte[0];
        }

        try {
            return new Base64URL(encoded).decode();
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(
                    "Failed to decode AAD from encryption context", e);
        }
    }
}

