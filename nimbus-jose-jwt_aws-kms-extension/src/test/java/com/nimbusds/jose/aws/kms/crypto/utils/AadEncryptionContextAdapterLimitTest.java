package com.nimbusds.jose.aws.kms.crypto.utils;

import org.junit.jupiter.api.Test;
import java.util.Map;
import static org.junit.jupiter.api.Assertions.*;

public class AadEncryptionContextAdapterLimitTest {

    @Test
    public void testAadSizeLimit() {
        // 1024 bytes is the limit for the JSON representation of the encryption context in KMS.
        // Base64URL encoding increases size by 4/3.
        // MAX_ENCODED_AAD_LENGTH is 1000 characters.
        // 1000 * 3/4 = 750 bytes.

        byte[] largeAad = new byte[750];
        for (int i = 0; i < largeAad.length; i++) {
            largeAad[i] = (byte) (i % 256);
        }

        Map<String, String> context = AadEncryptionContextAdapter.aadToEncryptionContext(largeAad);
        String encoded = context.get("_jose_aad");

        System.out.println("AAD length: " + largeAad.length);
        System.out.println("Encoded length: " + encoded.length());

        assertTrue(encoded.length() <= AadEncryptionContextAdapter.MAX_ENCODED_AAD_LENGTH);

        byte[] decoded = AadEncryptionContextAdapter.encryptionContextToAad(context);
        assertArrayEquals(largeAad, decoded);
    }

    @Test
    public void testAadSizeLimitExceeded() {
        // 751 bytes will result in 1002 characters (Base64URL encoded)
        // 750 bytes results in 1000 characters.
        byte[] tooLargeAad = new byte[751];
        assertThrows(IllegalArgumentException.class, () -> {
            AadEncryptionContextAdapter.aadToEncryptionContext(tooLargeAad);
        });
    }

    @Test
    void asdf() {}

}
