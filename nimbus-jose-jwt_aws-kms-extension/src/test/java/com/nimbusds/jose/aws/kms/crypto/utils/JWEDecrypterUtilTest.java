package com.nimbusds.jose.aws.kms.crypto.utils;

import com.nimbusds.jose.*;
import com.nimbusds.jose.aws.kms.crypto.aad.AadEncryptionContextConverter;
import com.nimbusds.jose.aws.kms.crypto.aad.DefaultAadEncryptionContextConverter;
import com.nimbusds.jose.aws.kms.crypto.testUtils.EasyRandomTestUtils;
import com.nimbusds.jose.aws.kms.exceptions.TemporaryJOSEException;
import com.nimbusds.jose.crypto.impl.AAD;
import com.nimbusds.jose.crypto.impl.ContentCryptoProvider;
import com.nimbusds.jose.jca.JWEJCAContext;
import com.nimbusds.jose.util.Base64URL;
import org.jeasy.random.EasyRandom;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.*;

import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.util.stream.Stream;

import static com.nimbusds.jose.aws.kms.crypto.impl.KmsDefaultEncryptionCryptoProvider.JWE_TO_KMS_ALGORITHM_SPEC;
import static com.nimbusds.jose.aws.kms.crypto.impl.KmsDefaultEncryptionCryptoProvider.SUPPORTED_ALGORITHMS;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

@DisplayName("For the JWEDecrypterUtil class,")
@ExtendWith(MockitoExtension.class)
public class JWEDecrypterUtilTest {

  static Stream<JWEHeader> supportedJWEAlgInHeader() {
    return SUPPORTED_ALGORITHMS.stream()
                               .map(alg -> new JWEHeader.Builder(alg, EncryptionMethod.A256GCM).build());
  }

  @Nested
  @DisplayName("the decrypt method,")
  class DecryptMethod {

    private final EasyRandom random = EasyRandomTestUtils.getEasyRandomWithByteBufferSupport();
    private String testKeyId;
    @Mock
    private JWEJCAContext mockJWEJCAContext;
    @Mock
    private KmsClient mockAwsKms;
    private JWEHeader testJweHeader;
    private final Base64URL testEncryptedKey = random.nextObject(Base64URL.class);
    private final Base64URL testIv = random.nextObject(Base64URL.class);
    private final Base64URL testCipherText = random.nextObject(Base64URL.class);
    private final Base64URL testAuthTag = random.nextObject(Base64URL.class);
    private AadEncryptionContextConverter aadEncryptionContextConverter = new DefaultAadEncryptionContextConverter();

    @BeforeEach
    void setUp() {
      testKeyId = random.nextObject(String.class);
      testJweHeader = new JWEHeader.Builder(
              JWEAlgorithm.RSA_OAEP_256,
              EncryptionMethod.A256GCM)
              .build();
      aadEncryptionContextConverter = new DefaultAadEncryptionContextConverter();
    }

    @Nested
    @DisplayName("with invalid key exception from KMS,")
    class WithInvalidKMSKeyException {

      KmsException parameterizedBeforeEach(final Class<KmsException> invalidKeyExceptionClass) {
        final KmsException invalidKeyException = mock(invalidKeyExceptionClass);
        when(mockAwsKms
                .decrypt(DecryptRequest.builder()
                                       .encryptionContext(aadEncryptionContextConverter.aadToEncryptionContext(AAD.compute(testJweHeader)))
                                       .keyId(testKeyId)
                                       .encryptionAlgorithm(JWE_TO_KMS_ALGORITHM_SPEC.get(testJweHeader.getAlgorithm()))
                                       .ciphertextBlob(SdkBytes.fromByteBuffer(ByteBuffer.wrap(testEncryptedKey.decode())))
                                       .build()))
                .thenThrow(invalidKeyException);

        return invalidKeyException;
      }

      @ParameterizedTest
      @DisplayName("should throw RemoteKeySourceException.")
      @ValueSource(classes = {
              NotFoundException.class, DisabledException.class, InvalidKeyUsageException.class,
              KeyUnavailableException.class, KmsInvalidStateException.class})
      void shouldThrowRemoteKeySourceException(final Class<KmsException> invalidKeyExceptionClass) {
        final KmsException invalidKeyException = parameterizedBeforeEach(invalidKeyExceptionClass);
        assertThatThrownBy(
                () -> JWEDecrypterUtil.decrypt(mockAwsKms, testKeyId, testJweHeader,
                        testEncryptedKey, testIv, testCipherText, testAuthTag, AAD.compute(testJweHeader), mockJWEJCAContext, aadEncryptionContextConverter))
                .isInstanceOf(RemoteKeySourceException.class)
                .hasMessage("An exception was thrown from KMS due to invalid key.")
                .hasCause(invalidKeyException);
      }
    }

    @Nested
    @DisplayName("with a temporary exception from KMS,")
    class WithTemporaryKMSException {

      KmsException parameterizedBeforeEach(final Class<KmsException> temporaryKMSExceptionClass) {
        final KmsException temporaryKMSException = mock(temporaryKMSExceptionClass);
        when(mockAwsKms
                .decrypt(DecryptRequest.builder()
                                       .encryptionContext(aadEncryptionContextConverter.aadToEncryptionContext(AAD.compute(testJweHeader)))
                                       .keyId(testKeyId)
                                       .encryptionAlgorithm(JWE_TO_KMS_ALGORITHM_SPEC.get(testJweHeader.getAlgorithm()))
                                       .ciphertextBlob(SdkBytes.fromByteBuffer(ByteBuffer.wrap(testEncryptedKey.decode())))
                                       .build()))
                .thenThrow(temporaryKMSException);

        return temporaryKMSException;
      }

      @ParameterizedTest
      @DisplayName("should throw TemporaryJOSEException.")
      @ValueSource(classes = {
              DependencyTimeoutException.class, InvalidGrantTokenException.class,
              KmsInternalException.class})
      void shouldThrowRemoteKeySourceException(final Class<KmsException> invalidKeyExceptionClass) {
        final KmsException invalidKeyException = parameterizedBeforeEach(invalidKeyExceptionClass);
        assertThatThrownBy(
                () -> JWEDecrypterUtil.decrypt(mockAwsKms, testKeyId, testJweHeader,
                        testEncryptedKey, testIv, testCipherText, testAuthTag, AAD.compute(testJweHeader), mockJWEJCAContext, aadEncryptionContextConverter))
                .isInstanceOf(TemporaryJOSEException.class)
                .hasMessage("A temporary error was thrown from KMS.")
                .hasCause(invalidKeyException);
      }
    }

    @Nested
    @DisplayName("with decryption result,")
    class WithDecryptionResult {

      private final DecryptResponse testDecryptResult = DecryptResponse.builder().plaintext(SdkBytes.fromString("test", Charset.defaultCharset())).build();
      private final MockedStatic<ContentCryptoProvider> mockContentCryptoProvider =
              mockStatic(ContentCryptoProvider.class);
      private final byte[] expectedData = new byte[random.nextInt(512)];

      void parameterizedBeforeEach(final JWEHeader jweHeader) {
        when(mockAwsKms
                .decrypt(DecryptRequest.builder()
                                       .encryptionContext(aadEncryptionContextConverter.aadToEncryptionContext(AAD.compute(testJweHeader)))
                                       .keyId(testKeyId)
                                       .encryptionAlgorithm(JWE_TO_KMS_ALGORITHM_SPEC.get(jweHeader.getAlgorithm()))
                                       .ciphertextBlob(SdkBytes.fromByteBuffer(ByteBuffer.wrap(testEncryptedKey.decode())))
                                       .build()))
                .thenReturn(testDecryptResult);

        random.nextBytes(expectedData);
        mockContentCryptoProvider.when(
                                         () -> ContentCryptoProvider.decrypt(
                                                 jweHeader, AAD.compute(testJweHeader), testEncryptedKey, testIv, testCipherText, testAuthTag,
                                                 new SecretKeySpec(
                                                         testDecryptResult.plaintext().asByteArray(),
                                                         jweHeader.getAlgorithm().toString()),
                                                 mockJWEJCAContext))
                                 .thenReturn(expectedData);
      }

      @ParameterizedTest
      @DisplayName("should return decrypted data,")
      @MethodSource("com.nimbusds.jose.aws.kms.crypto.utils.JWEDecrypterUtilTest#supportedJWEAlgInHeader")
      void shouldReturnDecryptedData(final JWEHeader jweHeader) throws JOSEException {
        parameterizedBeforeEach(jweHeader);
        final byte[] actualData = JWEDecrypterUtil.decrypt(mockAwsKms, testKeyId,
                jweHeader, testEncryptedKey, testIv, testCipherText, testAuthTag, AAD.compute(testJweHeader), mockJWEJCAContext, aadEncryptionContextConverter);
        assertThat(actualData).isEqualTo(expectedData);
      }

      @AfterEach
      void afterEach() {
        mockContentCryptoProvider.close();
      }
    }
  }
}
