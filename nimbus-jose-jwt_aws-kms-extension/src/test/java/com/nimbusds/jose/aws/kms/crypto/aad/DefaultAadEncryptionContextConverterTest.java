package com.nimbusds.jose.aws.kms.crypto.aad;

import com.nimbusds.jose.*;
import com.nimbusds.jose.aws.kms.crypto.KmsDefaultEncrypter;
import com.nimbusds.jose.aws.kms.crypto.KmsSymmetricEncrypter;
import com.nimbusds.jose.crypto.impl.AAD;
import com.nimbusds.jose.util.Base64URL;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.EncryptRequest;
import software.amazon.awssdk.services.kms.model.EncryptResponse;
import software.amazon.awssdk.services.kms.model.GenerateDataKeyRequest;
import software.amazon.awssdk.services.kms.model.GenerateDataKeyResponse;

import java.nio.charset.StandardCharsets;
import java.util.Map;

import static org.assertj.core.api.Assertions.*;
import static org.assertj.core.api.InstanceOfAssertFactories.BYTE_ARRAY;
import static org.assertj.core.api.SoftAssertions.assertSoftly;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

public class DefaultAadEncryptionContextConverterTest {
    @Nested
    class MockedKmsClientTests {
        private KmsClient mockKms;
        private final String keyId = "test-key-id";

        @BeforeEach
        void setUp() {
            mockKms = mock(KmsClient.class);
        }

        // TODO: not convinved we've covered all test cases here - JH
        @Test
        public void testNoAadNoEncryptionContext_DefaultEncrypter() throws Exception {
            KmsDefaultEncrypter encrypter = new KmsDefaultEncrypter(mockKms, keyId);

            EncryptResponse response = EncryptResponse.builder()
                    .ciphertextBlob(SdkBytes.fromByteArray(new byte[32]))
                    .build();
            when(mockKms.encrypt(any(EncryptRequest.class))).thenReturn(response);

            JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM).build();
            byte[] clearText = "hello".getBytes(StandardCharsets.UTF_8);

            encrypter.encrypt(header, clearText, AAD.compute(header));

            ArgumentCaptor<EncryptRequest> captor = ArgumentCaptor.forClass(EncryptRequest.class);
            verify(mockKms).encrypt(captor.capture());

            Map<String, String> context = captor.getValue().encryptionContext();
            byte[] expectedAad = AAD.compute(header);
            String expectedEncodedAad = Base64URL.encode(expectedAad).toString();

            assertThat(context).containsExactly(entry(DefaultAadEncryptionContextConverter.AAD_CONTEXT_KEY, expectedEncodedAad));
        }

        @Test
        public void testAadProvided_DefaultEncrypter() throws Exception {
            KmsDefaultEncrypter encrypter = new KmsDefaultEncrypter(mockKms, keyId);

            EncryptResponse response = EncryptResponse.builder()
                    .ciphertextBlob(SdkBytes.fromByteArray(new byte[32]))
                    .build();
            when(mockKms.encrypt(any(EncryptRequest.class))).thenReturn(response);

            JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM).build();
            byte[] clearText = "hello".getBytes(StandardCharsets.UTF_8);
            byte[] customAad = "custom-aad".getBytes(StandardCharsets.UTF_8);

            encrypter.encrypt(header, clearText, customAad);

            ArgumentCaptor<EncryptRequest> captor = ArgumentCaptor.forClass(EncryptRequest.class);
            verify(mockKms).encrypt(captor.capture());

            Map<String, String> context = captor.getValue().encryptionContext();
            String expectedEncodedAad = Base64URL.encode(customAad).toString();

            assertThat(context).containsExactly(entry(DefaultAadEncryptionContextConverter.AAD_CONTEXT_KEY, expectedEncodedAad));
        }

        @Test
        public void testNoAad_SymmetricEncrypter() throws Exception {
            KmsSymmetricEncrypter encrypter = new KmsSymmetricEncrypter(mockKms, keyId);

            GenerateDataKeyResponse response = GenerateDataKeyResponse.builder()
                    .plaintext(SdkBytes.fromByteArray(new byte[32]))
                    .ciphertextBlob(SdkBytes.fromByteArray(new byte[32]))
                    .build();
            when(mockKms.generateDataKey(any(GenerateDataKeyRequest.class))).thenReturn(response);

            JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.parse("SYMMETRIC_DEFAULT"), EncryptionMethod.A256GCM).build();
            byte[] clearText = "hello".getBytes(StandardCharsets.UTF_8);

            encrypter.encrypt(header, clearText, AAD.compute(header));

            ArgumentCaptor<GenerateDataKeyRequest> captor = ArgumentCaptor.forClass(GenerateDataKeyRequest.class);
            verify(mockKms).generateDataKey(captor.capture());

            Map<String, String> context = captor.getValue().encryptionContext();
            byte[] expectedAad = AAD.compute(header);
            String expectedEncodedAad = Base64URL.encode(expectedAad).toString();

            assertThat(context).containsExactly(entry(DefaultAadEncryptionContextConverter.AAD_CONTEXT_KEY, expectedEncodedAad));
        }
    }

    @Nested
    class AadSizeLimitTest {
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
}
