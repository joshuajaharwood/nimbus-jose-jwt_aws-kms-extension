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
import com.nimbusds.jose.aws.kms.crypto.impl.KmsDefaultEncryptionCryptoProvider;
import com.nimbusds.jose.aws.kms.exceptions.TemporaryJOSEException;
import com.nimbusds.jose.crypto.impl.ContentCryptoProvider;
import com.nimbusds.jose.util.Base64URL;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.*;

import javax.annotation.concurrent.ThreadSafe;
import javax.crypto.SecretKey;
import java.nio.ByteBuffer;
import java.util.Map;

import static com.nimbusds.jose.JWEAlgorithm.Family.SYMMETRIC;

/**
 * Encrypter implementation for a symmetric or asymmetric key stored in AWS KMS.
 * <p>
 * See {@link KmsDefaultEncryptionCryptoProvider} for supported algorithms and encryption methods,
 * and for details of various constructor parameters.
 */
@ThreadSafe
public class KmsDefaultEncrypter extends KmsDefaultEncryptionCryptoProvider implements JWEEncrypter {

    private static final Logger LOG = LoggerFactory.getLogger(KmsDefaultEncrypter.class);
    private static final JWEAlgorithm SYMMETRIC_DEFAULT = JWEAlgorithm.parse(EncryptionAlgorithmSpec.SYMMETRIC_DEFAULT.toString());
    private static final ImmutableSet<JWEAlgorithm> SYMMETRIC_ALGORITHMS = ImmutableSet.<JWEAlgorithm>builder().addAll(SYMMETRIC).add(SYMMETRIC_DEFAULT).build();


    public KmsDefaultEncrypter(final KmsClient kms,
                               final String keyId) {
        super(kms, keyId);
    }

    public KmsDefaultEncrypter(final KmsClient kms,
                               final String keyId,
                               final AadEncryptionContextConverter aadEncryptionContextConverter) {
        super(kms, keyId, aadEncryptionContextConverter);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public JWECryptoParts encrypt(final JWEHeader header, final byte[] clearText, final byte[] aad)
            throws JOSEException {

        validateJWEHeader(header);

        final SecretKey cek = ContentCryptoProvider.generateCEK(
                header.getEncryptionMethod(), getJCAContext().getSecureRandom());

        Map<String, String> kmsEncryptionContext = null;

        if (SYMMETRIC_ALGORITHMS.contains(header.getAlgorithm())) {
            LOG.debug("Symmetric algorithm selected. Encryption context will be used. [Algorithm: {}]", header.getAlgorithm());

            kmsEncryptionContext = getAadEncryptionContextConverter().aadToEncryptionContext(aad);
        } else {
            LOG.debug("Asymmetric algorithm selected. Encryption context will not be used. [Algorithm: {}]", header.getAlgorithm());
        }

        final EncryptResponse encryptedKey = encryptCEK(getKeyId(), header.getAlgorithm(), kmsEncryptionContext, cek);
        final Base64URL encodedEncryptedKey = Base64URL.encode(encryptedKey.ciphertextBlob().asByteArray());

        return ContentCryptoProvider.encrypt(header, clearText, aad, cek, encodedEncryptedKey, getJCAContext());
    }

    private EncryptResponse encryptCEK(String keyId, JWEAlgorithm alg, @Nullable Map<String, String> encryptionContext,
                                       SecretKey cek)
            throws JOSEException {
        try {
            LOG.debug("Encrypting locally-generated CEK using AWS KMS...");

            EncryptRequest.Builder builder = EncryptRequest.builder()
                    .keyId(keyId)
                    .encryptionAlgorithm(JWE_TO_KMS_ALGORITHM_SPEC.get(alg))
                    .plaintext(SdkBytes.fromByteBuffer(ByteBuffer.wrap(cek.getEncoded())));

            if (encryptionContext != null) {
                builder.encryptionContext(encryptionContext);
            }

            EncryptResponse encrypt = getKms().encrypt(builder.build());

            LOG.debug("CEK encrypted.");

            return encrypt;
        } catch (NotFoundException | DisabledException | InvalidKeyUsageException
                 | KmsInvalidStateException | InvalidGrantTokenException e) {
            throw new RemoteKeySourceException("An exception was thrown from KMS due to invalid client request.", e);
        } catch (DependencyTimeoutException | KeyUnavailableException | KmsInternalException e) {
            throw new TemporaryJOSEException("A temporary error was thrown from KMS.", e);
        }
    }
}
