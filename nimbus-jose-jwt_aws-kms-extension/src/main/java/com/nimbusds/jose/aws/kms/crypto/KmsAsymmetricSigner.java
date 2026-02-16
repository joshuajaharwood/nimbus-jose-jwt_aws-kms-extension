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


import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.RemoteKeySourceException;
import com.nimbusds.jose.aws.kms.crypto.impl.KmsAsymmetricSigningCryptoProvider;
import com.nimbusds.jose.aws.kms.exceptions.TemporaryJOSEException;
import com.nimbusds.jose.util.Base64URL;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.*;

import javax.annotation.concurrent.ThreadSafe;
import java.nio.ByteBuffer;
import java.util.Optional;

/**
 * Signer implementation for asymmetric signing with public/private key stored in AWS KMS.
 * <p>
 * See {@link KmsAsymmetricSigningCryptoProvider} for supported algorithms, and for details of various
 * constructor parameters.
 */
@ThreadSafe
public class KmsAsymmetricSigner extends KmsAsymmetricSigningCryptoProvider implements JWSSigner {
    private static final Logger LOG = LoggerFactory.getLogger(KmsAsymmetricSigner.class);

    public KmsAsymmetricSigner(
            final KmsClient kms, final String privateKeyId, final MessageType messageType) {
        super(kms, privateKeyId, messageType);
    }

    @Override
    public Base64URL sign(final JWSHeader header, final byte[] signingInput) throws JOSEException {
        LOG.info("Signing payload...");

        final ByteBuffer message = getMessage(header, signingInput);
        SignResponse signResponse;
        try {
            // We've already checked if the given algorithm is mapped in KmsAsymmetricSigningCryptoProvider
            SigningAlgorithmSpec signingAlgorithmSpec = JWS_ALGORITHM_TO_SIGNING_ALGORITHM_SPEC.get(header.getAlgorithm());

            LOG.debug("Sending sign request to AWS KMS... [Payload length: {}] [Signing algorithm: {}]",
                    signingInput.length,
                    signingAlgorithmSpec);

            signResponse = getKms()
                    .sign(SignRequest.builder()
                    .keyId(getPrivateKeyId())
                    .messageType(getMessageType())
                    .message(SdkBytes.fromByteBuffer(message))
                    .signingAlgorithm(signingAlgorithmSpec)
                    .build());

            LOG.debug("Sign response received.");
        } catch (NotFoundException | DisabledException | KeyUnavailableException | InvalidKeyUsageException
                 | KmsInvalidStateException e) {
            throw new RemoteKeySourceException("An exception was thrown from KMS due to invalid key.", e);
        } catch (DependencyTimeoutException | InvalidGrantTokenException | KmsInternalException e) {
            throw new TemporaryJOSEException("A temporary exception was thrown from KMS.", e);
        }

        Base64URL encoded = Base64URL.encode(signResponse.signature().asByteArray());

        LOG.info("Payload signed.");

        return encoded;
    }
}
