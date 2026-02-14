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

import com.google.common.collect.ImmutableSet;
import com.nimbusds.jose.*;
import com.nimbusds.jose.aws.kms.crypto.aad.AadEncryptionContextConverter;
import com.nimbusds.jose.aws.kms.crypto.aad.DefaultAadEncryptionContextConverter;
import com.nimbusds.jose.aws.kms.crypto.testUtils.EasyRandomTestUtils;
import com.nimbusds.jose.aws.kms.crypto.utils.JWEDecrypterUtil;
import com.nimbusds.jose.aws.kms.exceptions.TemporaryJOSEException;
import com.nimbusds.jose.crypto.impl.AAD;
import com.nimbusds.jose.crypto.impl.ContentCryptoProvider;
import com.nimbusds.jose.crypto.impl.CriticalHeaderParamsDeferral;
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
import software.amazon.awssdk.services.kms.model.DecryptRequest;
import software.amazon.awssdk.services.kms.model.DecryptResponse;
import software.amazon.awssdk.services.kms.model.EncryptionAlgorithmSpec;

import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.util.Set;

import static com.nimbusds.jose.aws.kms.crypto.impl.KmsDefaultEncryptionCryptoProvider.JWE_TO_KMS_ALGORITHM_SPEC;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

@DisplayName("For KmsDefaultDecrypter class, ")
@ExtendWith(MockitoExtension.class)
public class KmsDefaultDecrypterTest {

    private final EasyRandom random = EasyRandomTestUtils.getEasyRandomWithByteBufferSupport();

    @Mock
    private KmsClient mockAwsKms;
    private String testKeyId;
    private Set<String> testDeferredCriticalHeaders;
    private KmsDefaultDecrypter kmsDefaultDecrypter;
    private AadEncryptionContextConverter aadEncryptionContextConverter;

    @BeforeEach
    void setUp() {
        testKeyId = random.nextObject(String.class);
        testDeferredCriticalHeaders = ImmutableSet.of("test-deferred-critical-header");
        aadEncryptionContextConverter = new DefaultAadEncryptionContextConverter();
    }

    @Nested
    @DisplayName("the getProcessedCriticalHeaderParams method,")
    class GetProcessedCriticalHeaderParams {

        @BeforeEach
        void beforeEach() {
            kmsDefaultDecrypter = new KmsDefaultDecrypter(mockAwsKms, testKeyId);
        }

        @Test
        @DisplayName("should return processed critical headers.")
        void shouldReturnProcessedCriticalHeaders() {
            final Set<String> actualProcessedCriticalHeader = kmsDefaultDecrypter.getProcessedCriticalHeaderParams();
            assertThat(actualProcessedCriticalHeader)
                    .isEqualTo(new CriticalHeaderParamsDeferral().getProcessedCriticalHeaderParams());
        }
    }

    @Nested
    @DisplayName("the getDeferredCriticalHeaderParams method,")
    class GetDeferredCriticalHeaderParams {

        @BeforeEach
        void beforeEach() {
            kmsDefaultDecrypter = new KmsDefaultDecrypter(mockAwsKms, testKeyId, testDeferredCriticalHeaders);
        }

        @Test
        @DisplayName("should return deferred critical headers.")
        void shouldReturnDeferredCriticalHeaders() {
            final Set<String> actualDeferredCriticalHeader = kmsDefaultDecrypter.getDeferredCriticalHeaderParams();
            assertThat(actualDeferredCriticalHeader).isEqualTo(testDeferredCriticalHeaders);
        }
    }

    @Nested
    @DisplayName("the decrypt method,")
    class DecryptMethod {

        private JWEHeader testJweHeader;
        private final Base64URL testEncryptedKey = random.nextObject(Base64URL.class);
        private final Base64URL testIv = random.nextObject(Base64URL.class);
        private final Base64URL testCipherText = random.nextObject(Base64URL.class);
        private final Base64URL testAuthTag = random.nextObject(Base64URL.class);

        @BeforeEach
        void beforeEach() {
            kmsDefaultDecrypter = spy(new KmsDefaultDecrypter(mockAwsKms, testKeyId, testDeferredCriticalHeaders));
        }

        @Nested
        @DisplayName("with missing critical header,")
        class WithMissingCriticalHeader {

            @BeforeEach
            void beforeEach() throws NoSuchMethodException {
                testJweHeader = new JWEHeader.Builder(
                        JWEAlgorithm.RSA_OAEP_256,
                        EncryptionMethod.A256GCM)
                        .criticalParams(ImmutableSet.of("test-critical-header"))
                        .build();
                ReflectionSupport.invokeMethod(
                        kmsDefaultDecrypter.getClass().getSuperclass()
                                .getDeclaredMethod("validateJWEHeader", JWEHeader.class),
                        doNothing().when(kmsDefaultDecrypter),
                        testJweHeader);
            }

            @Test
            @DisplayName("should throw JOSEException.")
            void shouldThrowJOSEException() {
                assertThatThrownBy(
                        () -> kmsDefaultDecrypter.decrypt(testJweHeader, testEncryptedKey, testIv, testCipherText,
                                testAuthTag, AAD.compute(testJweHeader)))
                        .isInstanceOf(JOSEException.class)
                        .hasNoCause();
            }
        }

        @Nested
        @DisplayName("with critical header,")
        class WithCriticalHeader {

            @Mock
            private JWEJCAContext mockJWEJCAContext;
            private final DecryptResponse testDecryptResponse = DecryptResponse.builder().plaintext(SdkBytes.fromString("test", Charset.defaultCharset())).build();
            private final MockedStatic<ContentCryptoProvider> mockContentCryptoProvider =
                    mockStatic(ContentCryptoProvider.class);
            private final byte[] expectedData = new byte[random.nextInt(512)];

            @BeforeEach
            void beforeEach() {
                testJweHeader = new JWEHeader.Builder(
                        JWEAlgorithm.parse(EncryptionAlgorithmSpec.RSAES_OAEP_SHA_256.toString()),
                        EncryptionMethod.A256GCM)
                        .criticalParams(testDeferredCriticalHeaders)
                        .build();
                random.nextBytes(expectedData);
                mockContentCryptoProvider.when(
                                () -> ContentCryptoProvider.decrypt(
                                        testJweHeader, AAD.compute(testJweHeader), testEncryptedKey, testIv, testCipherText, testAuthTag,
                                        new SecretKeySpec(
                                                testDecryptResponse.plaintext().asByteArray(),
                                                testJweHeader.getAlgorithm().toString()),
                                        kmsDefaultDecrypter.getJCAContext()))
                        .thenReturn(expectedData);
                when(kmsDefaultDecrypter.getJCAContext()).thenReturn(mockJWEJCAContext);
            }

            @Nested
            @DisplayName("with exception thrown from JWEDecrypterUtil,")
            class WithExceptionThrownFromJWEDecrypterUtil {

                @ParameterizedTest
                @DisplayName("should throw exception.")
                @ValueSource(classes = {
                        JOSEException.class, RemoteKeySourceException.class, TemporaryJOSEException.class
                })
                void shouldThrowException(final Class<Throwable> exceptionClass) {
                    byte[] aad = AAD.compute(testJweHeader);

                    try (MockedStatic<JWEDecrypterUtil> utilMockedStatic = mockStatic(JWEDecrypterUtil.class)) {
                        utilMockedStatic.when(() -> JWEDecrypterUtil.decrypt(
                                eq(mockAwsKms),
                                eq(testKeyId),
                                eq(testJweHeader),
                                eq(testEncryptedKey),
                                eq(testIv),
                                eq(testCipherText),
                                eq(testAuthTag),
                                eq(aad),
                                eq(mockJWEJCAContext),
                                any(AadEncryptionContextConverter.class)))                                .thenThrow(exceptionClass);
                        assertThatExceptionOfType(exceptionClass).isThrownBy(() -> kmsDefaultDecrypter.decrypt(
                                testJweHeader, testEncryptedKey, testIv, testCipherText, testAuthTag, aad));
                    }
                }
            }

            @Nested
            @DisplayName("with decryption result from JWEDecrypterUtil,")
            class WithDecryptionResultFromJWEDecrypterUtil {

                @BeforeEach
                void beforeEach() throws JOSEException {
                    when(mockAwsKms
                            .decrypt(DecryptRequest.builder()
                                    .encryptionContext(aadEncryptionContextConverter.aadToEncryptionContext(AAD.compute(testJweHeader)))
                                    .encryptionAlgorithm(JWE_TO_KMS_ALGORITHM_SPEC.get(testJweHeader.getAlgorithm()))
                                    .keyId(testKeyId)
                                    .ciphertextBlob(SdkBytes.fromByteBuffer(ByteBuffer.wrap(testEncryptedKey.decode())))
                                    .build()))
                            .thenReturn(testDecryptResponse);
                    when(JWEDecrypterUtil.decrypt(mockAwsKms, testKeyId,
                            testJweHeader, testEncryptedKey, testIv, testCipherText,
                            testAuthTag, AAD.compute(testJweHeader), mockJWEJCAContext, aadEncryptionContextConverter))
                            .thenReturn(expectedData);
                }

                @Test
                @DisplayName("should return decrypted data.")
                void shouldReturnDecryptedData() throws JOSEException {
                    final byte[] actualData = kmsDefaultDecrypter.decrypt(
                            testJweHeader, testEncryptedKey, testIv, testCipherText, testAuthTag, AAD.compute(testJweHeader));
                    assertThat(actualData).isEqualTo(expectedData);
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
                    kmsDefaultDecrypter.getClass().getSuperclass()
                            .getDeclaredMethod("validateJWEHeader", JWEHeader.class),
                    verify(kmsDefaultDecrypter),
                    testJweHeader);
        }
    }
}
