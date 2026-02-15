package com.nimbusds.jose.aws.kms.crypto.utils;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.nimbusds.jose.*;
import com.nimbusds.jose.aws.kms.crypto.aad.AadEncryptionContextConverter;
import com.nimbusds.jose.aws.kms.exceptions.TemporaryJOSEException;
import com.nimbusds.jose.crypto.impl.ContentCryptoProvider;
import com.nimbusds.jose.jca.JWEJCAContext;
import com.nimbusds.jose.util.ArrayUtils;
import com.nimbusds.jose.util.Base64URL;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.*;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Map;

import static com.nimbusds.jose.JWEAlgorithm.Family.SYMMETRIC;
import static com.nimbusds.jose.aws.kms.crypto.impl.KmsDefaultEncryptionCryptoProvider.JWE_TO_KMS_ALGORITHM_SPEC;

/**
 * Utility class containing JWE decryption-related methods.
 */
public final class JWEDecrypterUtil {
    private static final Logger LOG = LoggerFactory.getLogger(JWEDecrypterUtil.class);
    private static final JWEAlgorithm SYMMETRIC_DEFAULT = JWEAlgorithm.parse(EncryptionAlgorithmSpec.SYMMETRIC_DEFAULT.toString());
    private static final ImmutableSet<JWEAlgorithm> SYMMETRIC_ALGORITHMS = ImmutableSet.<JWEAlgorithm>builder().addAll(SYMMETRIC).add(SYMMETRIC_DEFAULT).build();

    private JWEDecrypterUtil() {
    }

    /**
     * Decrypts the specified cipher text of a {@link JWEObject JWE Object}.
     *
     * @throws RemoteKeySourceException in case exception is thrown from KMS due to invalid key
     * @throws TemporaryJOSEException   in case temporary error is thrown from KMS
     */
    public static byte[] decrypt(
            KmsClient kms,
            String keyId,
            JWEHeader header,
            Base64URL encryptedKey,
            Base64URL iv,
            Base64URL cipherText,
            Base64URL authTag,
            byte[] aad,
            JWEJCAContext jcaContext,
            AadEncryptionContextConverter aadEncryptionContextConverter)
            throws JOSEException {

        LOG.info("Beginning decryption... ");

        Map<String, String> kmsEncryptionContext = null;

        if (SYMMETRIC_ALGORITHMS.contains(header.getAlgorithm())) {
            LOG.info("Symmetric algorithm selected. Encryption context will be used. [Algorithm: {}]", header.getAlgorithm());
            kmsEncryptionContext = aadEncryptionContextConverter.aadToEncryptionContext(aad);
        } else {
            LOG.info("Asymmetric algorithm selected. Encryption context will not be used. [Algorithm: {}]", header.getAlgorithm());
        }

        final DecryptResponse cekDecryptResult =
                decryptCek(kms, keyId, kmsEncryptionContext, header.getAlgorithm(), encryptedKey);

        final SecretKey cek =
                new SecretKeySpec(cekDecryptResult.plaintext().asByteArray(), header.getAlgorithm().toString());

        LOG.info("Performing decryption of ciphertext with decrypted CEK...");

        byte[] decryptionResult = ContentCryptoProvider.decrypt(header, aad, encryptedKey, iv, cipherText, authTag, cek, jcaContext);

        LOG.info("Decrypted ciphertext.");

        return decryptionResult;
    }

    private static DecryptResponse decryptCek(
            KmsClient kms,
            String keyId,
            @Nullable Map<String, String> encryptionContext,
            JWEAlgorithm alg,
            Base64URL encryptedKey
    ) throws JOSEException {
        try {
            final String algorithm = JWE_TO_KMS_ALGORITHM_SPEC.get(alg);

            LOG.info("Decrypting encrypted CEK with AWS KMS... [Key ID: {}] [Encryption context: {}] [Encryption algorithm: {}]",
                    keyId,
                    encryptionContext,
                    algorithm);

            DecryptRequest.Builder builder = DecryptRequest.builder()
                    .keyId(keyId)
                    .encryptionAlgorithm(algorithm)
                    .ciphertextBlob(SdkBytes.fromByteArray(encryptedKey.decode()));

            if (encryptionContext != null) {
                builder.encryptionContext(encryptionContext);
            }

            final DecryptResponse decrypt = kms.decrypt(builder.build());

            LOG.info("Received CEK decryption result from AWS KMS. [Key ID: {}] [Encryption context: {}] [Encryption algorithm: {}] [Response metadata: {}]",
                    keyId,
                    encryptionContext,
                    algorithm,
                    decrypt.responseMetadata().requestId());

            return decrypt;
        } catch (NotFoundException | DisabledException | InvalidKeyUsageException | KeyUnavailableException
                 | KmsInvalidStateException e) {
            throw new RemoteKeySourceException("An exception was thrown from KMS due to invalid key.", e);
        } catch (DependencyTimeoutException | InvalidGrantTokenException | KmsInternalException e) {
            throw new TemporaryJOSEException("A temporary error was thrown from KMS.", e);
        }
    }
}
