package com.nimbusds.jose.aws.kms.crypto.aadec;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.*;
import static org.assertj.core.api.InstanceOfAssertFactories.BYTE_ARRAY;
import static org.assertj.core.api.SoftAssertions.assertSoftly;

class DefaultAadEncryptionContextConverterTest {

    private DefaultAadEncryptionContextConverter defaultAadEncryptionContextConverter;

    @BeforeEach
    void setUp() {
        defaultAadEncryptionContextConverter = new DefaultAadEncryptionContextConverter();
    }

    @Test
    void testAadSizeLimit() {
        assertSoftly(softly -> {
            // 1024 bytes is the limit for the JSON representation of the encryption context in KMS.
            // Base64URL encoding increases size by 4/3.
            // MAX_ENCODED_AAD_LENGTH is 1000 characters.
            // 1000 * 3/4 = 750 bytes.

            byte[] largeAad = new byte[750];
            for (int i = 0; i < largeAad.length; i++) {
                largeAad[i] = (byte) (i % 256);
            }

            Map<String, String> context = defaultAadEncryptionContextConverter.aadToEncryptionContext(largeAad);
            String encoded = context.get(DefaultAadEncryptionContextConverter.AAD_CONTEXT_KEY);

            softly.assertThatObject(encoded)
                    .as("encoded string is not null")
                    .isNotNull()
                    .extracting(String::getBytes, BYTE_ARRAY)
                    .as("encoded string as bytes has size under or equal to limit")
                    .hasSizeLessThanOrEqualTo(DefaultAadEncryptionContextConverter.MAX_ENCODED_AAD_LENGTH);

            softly.assertThat(defaultAadEncryptionContextConverter.encryptionContextToAad(context))
                    .isEqualTo(largeAad);
        });
    }

    @Test
    void testAadSizeLimitExceeded() {
        // 751 bytes will result in 1002 characters (Base64URL encoded)
        // 750 bytes results in 1000 characters.
        assertThatIllegalArgumentException()
                .isThrownBy(() -> defaultAadEncryptionContextConverter.aadToEncryptionContext(new byte[751]));
    }
}