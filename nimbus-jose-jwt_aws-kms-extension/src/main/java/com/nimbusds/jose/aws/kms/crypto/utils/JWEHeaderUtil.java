package com.nimbusds.jose.aws.kms.crypto.utils;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.crypto.impl.AlgorithmSupportMessage;

import java.util.Set;

/**
 * Utility class containing JWE header related methods.
 */
public final class JWEHeaderUtil {
    private JWEHeaderUtil() {
    }

    /**
     * Method to validation the algorithm and encryption-method of the passed JWE header.
     */
    public static void validateJWEHeaderAlgorithms(
            final JWEHeader header,
            Set<JWEAlgorithm> supportedAlgorithms,
            Set<EncryptionMethod> supportedEncryptionMethods) throws JOSEException {
        final JWEAlgorithm alg = header.getAlgorithm();
        final EncryptionMethod enc = header.getEncryptionMethod();

        if (!supportedAlgorithms.contains(alg)) {
            throw new JOSEException(AlgorithmSupportMessage.unsupportedJWEAlgorithm(alg, supportedAlgorithms));
        }

        if (!supportedEncryptionMethods.contains(enc)) {
            throw new JOSEException(
                    AlgorithmSupportMessage.unsupportedEncryptionMethod(enc, supportedEncryptionMethods));
        }
    }
}
