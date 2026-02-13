package com.nimbusds.jose.aws.kms.crypto;

import com.google.common.collect.ImmutableMap;

import java.util.Map;

/**
 * Adapter to convert between JOSE AAD (Additional Authenticated Data) byte arrays
 * and AWS KMS encryption context maps.
 */
public interface AadEncryptionContextConverter {
    /**
     * Converts AAD bytes to an encryption context map.
     *
     * @param aad Additional Authenticated Data as byte array (typically the JOSE protected header)
     * @return Map containing the base64url-encoded AAD
     */
    ImmutableMap<String, String> aadToEncryptionContext(final byte[] aad);

    /**
     * Extracts AAD bytes from an encryption context map.
     *
     * @param encryptionContext The encryption context map from KMS
     * @return The decoded AAD bytes, or empty array if not present
     */
    byte[] encryptionContextToAad(final Map<String, String> encryptionContext);
}
