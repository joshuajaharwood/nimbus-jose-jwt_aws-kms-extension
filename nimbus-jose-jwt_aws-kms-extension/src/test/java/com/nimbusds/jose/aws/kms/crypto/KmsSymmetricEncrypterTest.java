/*
  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.

  Licensed under the Apache License, Version 2.0 (the "License").
  You may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
 */

package com.nimbusds.jose.aws.kms.crypto;

import com.google.common.collect.ImmutableMap;
import com.nimbusds.jose.*;
import com.nimbusds.jose.aws.kms.crypto.impl.KmsSymmetricCryptoProvider;
import com.nimbusds.jose.aws.kms.crypto.testUtils.EasyRandomTestUtils;
import com.nimbusds.jose.aws.kms.exceptions.TemporaryJOSEException;
import com.nimbusds.jose.crypto.impl.AAD;
import com.nimbusds.jose.crypto.impl.ContentCryptoProvider;
import com.nimbusds.jose.jca.JWEJCAContext;
import com.nimbusds.jose.util.Base64URL;
import org.jeasy.random.EasyRandom;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.platform.commons.support.ReflectionSupport;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.*;

import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.Charset;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.refEq;
import static org.mockito.Mockito.*;

@DisplayName("For KmsSymmetricEncrypter class,")
@ExtendWith(MockitoExtension.class)
class KmsSymmetricEncrypterTest {

    private final EasyRandom random = EasyRandomTestUtils.getEasyRandomWithByteBufferSupport();

    @Mock
    private KmsClient mockAwsKms;
    private final String testKeyId = random.nextObject(String.class);
    private final Map<String, String> testEncryptionContext = random.nextObject(Map.class);

    private KmsSymmetricEncrypter kmsSymmetricEncrypter;

    @BeforeEach
    void beforeEach() {
        kmsSymmetricEncrypter = spy(new KmsSymmetricEncrypter(mockAwsKms, testKeyId, testEncryptionContext));
    }

    @Nested
    @DisplayName("the encrypt method,")
    class EncryptMethod {

        private JWEHeader testJweHeader;
        private final byte[] testClearText = new byte[random.nextInt(512)];

        @BeforeEach
        void beforeEach() throws NoSuchMethodException {
            random.nextBytes(testClearText);
            testJweHeader = new JWEHeader.Builder(
                    JWEAlgorithm.parse(EncryptionAlgorithmSpec.SYMMETRIC_DEFAULT.toString()),
                    EncryptionMethod.A256GCM)
                    .build();
            ReflectionSupport.invokeMethod(
                    kmsSymmetricEncrypter.getClass().getSuperclass()
                            .getDeclaredMethod("validateJWEHeader", JWEHeader.class),
                    doNothing().when(kmsSymmetricEncrypter),
                    testJweHeader);
        }

        @Nested
        @DisplayName("with invalid key exception from KMS,")
        class WithInvalidKMSKeyException {

            KmsException parameterizedBeforeEach(final Class<KmsException> invalidKeyExceptionClass) {
                final KmsException invalidKeyException = mock(invalidKeyExceptionClass);
                when(mockAwsKms
                        .generateDataKey(any(GenerateDataKeyRequest.class)))
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
                assertThatThrownBy(() -> kmsSymmetricEncrypter.encrypt(testJweHeader, testClearText, null))
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
                        .generateDataKey(any(GenerateDataKeyRequest.class)))
                        .thenThrow(temporaryKMSException);

                return temporaryKMSException;
            }

            @ParameterizedTest
            @DisplayName("should throw RemoteKeySourceException.")
            @ValueSource(classes = {
                    DependencyTimeoutException.class, InvalidGrantTokenException.class,
                    KmsInternalException.class})
            void shouldThrowRemoteKeySourceException(final Class<KmsException> invalidKeyExceptionClass) {
                final KmsException invalidKeyException = parameterizedBeforeEach(invalidKeyExceptionClass);
                assertThatThrownBy(() -> kmsSymmetricEncrypter.encrypt(testJweHeader, testClearText, AAD.compute(testJweHeader)))
                        .isInstanceOf(TemporaryJOSEException.class)
                        .hasMessage("A temporary error was thrown from KMS.")
                        .hasCause(invalidKeyException);
            }
        }

        @Nested
        @DisplayName("with data-key from KMS,")
        class WithDataKey {

            private GenerateDataKeyResponse testGenerateDataKeyResponse;
            private final MockedStatic<ContentCryptoProvider> mockContentCryptoProvider =
                    mockStatic(ContentCryptoProvider.class);

            @Mock
            private JWECryptoParts mockJweCryptoParts;

            @BeforeEach
            void beforeEach() {
                testGenerateDataKeyResponse = GenerateDataKeyResponse.builder().plaintext(SdkBytes.fromString("test", Charset.defaultCharset())).ciphertextBlob(SdkBytes.fromString("test", Charset.defaultCharset())).build();
                when(mockAwsKms
                        .generateDataKey(any(GenerateDataKeyRequest.class)))
                        .thenReturn(testGenerateDataKeyResponse);
            }

            @Nested
            @DisplayName("without encryption context,")
            class WithoutEncryptionContext {

                @BeforeEach
                void beforeEach() throws NoSuchMethodException {
                    reset(kmsSymmetricEncrypter);
                    kmsSymmetricEncrypter = spy(new KmsSymmetricEncrypter(mockAwsKms, testKeyId));
                    ReflectionSupport.invokeMethod(
                            kmsSymmetricEncrypter.getClass().getSuperclass()
                                    .getDeclaredMethod("validateJWEHeader", JWEHeader.class),
                            doNothing().when(kmsSymmetricEncrypter),
                            testJweHeader);

                    final JWEJCAContext jcaContext = kmsSymmetricEncrypter.getJCAContext();
                    mockContentCryptoProvider.when(
                                    () -> ContentCryptoProvider.encrypt(
                                            testJweHeader,
                                            testClearText,
                                            null,
                                            new SecretKeySpec(testGenerateDataKeyResponse.plaintext().asByteArray(),
                                                    testJweHeader.getAlgorithm().toString()),
                                            Base64URL.encode(testGenerateDataKeyResponse.ciphertextBlob().asByteArray()),
                                            jcaContext))
                            .thenReturn(mockJweCryptoParts);

                    reset(mockAwsKms);
                    when(mockAwsKms
                            .generateDataKey(any(GenerateDataKeyRequest.class)))
                            .thenReturn(testGenerateDataKeyResponse);
                }

                @Test
                @DisplayName("should encrypt JWE token.")
                void shouldReturnEncryptedJWEToken() throws JOSEException {
                    final JWECryptoParts actualJweCryptoParts =
                            kmsSymmetricEncrypter.encrypt(testJweHeader, testClearText, null);
                    assertThat(actualJweCryptoParts).isSameAs(mockJweCryptoParts);
                }

            }

            @Nested
            @DisplayName("with encryption context,")
            class WithEncryptionContext {

                @BeforeEach
                void beforeEach() {
                    final JWEJCAContext jcaContext = kmsSymmetricEncrypter.getJCAContext();
                    mockContentCryptoProvider.when(
                                    () -> ContentCryptoProvider.encrypt(
                                            eq(testJweHeader),
                                            eq(testClearText),
                                            isNull(),
                                            eq(new SecretKeySpec(
                                                    testGenerateDataKeyResponse.plaintext().asByteArray(),
                                                    testJweHeader.getAlgorithm().toString())),
                                            eq(Base64URL.encode(
                                                    testGenerateDataKeyResponse.ciphertextBlob().asByteArray())),
                                            eq(jcaContext)))
                            .thenReturn(mockJweCryptoParts);
                }

                @Test
                @DisplayName("should encrypt JWE token.")
                void shouldReturnEncryptedJWEToken() throws JOSEException {
                    final JWECryptoParts actualJweCryptoParts =
                            kmsSymmetricEncrypter.encrypt(testJweHeader, testClearText, null);
                    assertThat(actualJweCryptoParts).isSameAs(mockJweCryptoParts);
                }

            }

            @AfterEach
            void afterEach() {
                mockContentCryptoProvider.close();
            }
        }

        @AfterEach
        void afterEach() throws NoSuchMethodException {
            ReflectionSupport.invokeMethod(
                    kmsSymmetricEncrypter.getClass().getSuperclass()
                            .getDeclaredMethod("validateJWEHeader", JWEHeader.class),
                    verify(kmsSymmetricEncrypter),
                    testJweHeader);
        }
    }
}
