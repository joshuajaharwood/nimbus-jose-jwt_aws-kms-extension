package com.nimbusds.jose.aws.kms.crypto.utils;

import com.nimbusds.jose.util.Base64URL;
import java.util.HashMap;
import java.util.Map;

/**
 * Adapter to convert between JOSE AAD (Additional Authenticated Data) byte arrays
 * and AWS KMS encryption context maps.
 * <p>
 * This allows the newer byte-array based AAD implementation in Nimbus JOSE+JWT
 * to work with AWS KMS's keypair encryption context.
 */
public class AadEncryptionContextAdapter {

  /**
   * Key used to store the AAD in the encryption context.
   * Using a prefixed key to avoid collisions with user-defined context.
   *
   * @see <a href="https://docs.aws.amazon.com/kms/latest/developerguide/encrypt_context.html">AWS KMS Encryption Context</a>
   */
  public static final String AAD_CONTEXT_KEY = "_jose_aad";

  /**
   * Maximum length of the base64url-encoded AAD string to ensure it fits within
   * the KMS encryption context limit.
   * The limit for the entire encryption context is 1024 bytes (JSON-encoded).
   * 1000 characters is a safe limit allowing for the key and some user context.
   * <p>
   * todo: check that this is definitely correct
   */
  public static final int MAX_ENCODED_AAD_LENGTH = 1000;

  /**
   * Converts AAD bytes to an encryption context map.
   *
   * @param aad Additional Authenticated Data as byte array (typically the JOSE protected header)
   * @return Map containing the base64url-encoded AAD
   */
  public static Map<String, String> aadToEncryptionContext(byte[] aad) {
    Map<String, String> context = new HashMap<>();

    if (aad != null && aad.length > 0) {
      // Use base64url encoding without padding (standard for JOSE)
      String encoded = Base64URL.encode(aad).toString();

      if (encoded.length() > MAX_ENCODED_AAD_LENGTH) {
        throw new IllegalArgumentException("Encoded AAD length exceeds the maximum supported size for KMS encryption context (" + MAX_ENCODED_AAD_LENGTH + " characters)");
      }

      context.put(AAD_CONTEXT_KEY, encoded);
    }

    return context;
  }

  /**
   * Extracts AAD bytes from an encryption context map.
   *
   * @param encryptionContext The encryption context map from KMS
   * @return The decoded AAD bytes, or empty array if not present
   */
  public static byte[] encryptionContextToAad(Map<String, String> encryptionContext) {
    if (encryptionContext == null) {
      return new byte[0];
    }

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