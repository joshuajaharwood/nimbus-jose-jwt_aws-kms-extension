package com.nimbusds.jose.aws.kms.crypto;

import com.nimbusds.jose.*;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.EncryptionAlgorithmSpec;
import software.amazon.awssdk.services.kms.model.MessageType;

import static org.assertj.core.api.Assertions.assertThat;

@Disabled
@Tag("LiveIntegration")
public class KmsLiveIntegrationTest {
    private String signingKeyId = "REPLACEME";
    private String encryptionKeyId = "REPLACEME";

    @Test
    void testDefaultEncrypterDecrypterEncryptsSuccessfully() throws Exception {
        KmsClient kmsClient = KmsClient.builder().region(Region.EU_WEST_1).build();
        String payload = "Hello, live KMS!";

        //TODO: last thing, make it so aad can't be passed in at kms level for asymmetric encryption
        JWEAlgorithm symmetricDefaultAlgo = JWEAlgorithm.parse(EncryptionAlgorithmSpec.SYMMETRIC_DEFAULT.toString());

        // 1. Encrypt
        JWEHeader header = new JWEHeader.Builder(symmetricDefaultAlgo, EncryptionMethod.A256GCM)
                .keyID(encryptionKeyId)
                .build();
        JWEObject jweObject = new JWEObject(header, new Payload(payload));

        KmsDefaultEncrypter encrypter = new KmsDefaultEncrypter(kmsClient, encryptionKeyId);
        jweObject.encrypt(encrypter);
        String serialized = jweObject.serialize();

        // 2. Decrypt
        JWEObject parsedJwe = JWEObject.parse(serialized);
        KmsDefaultDecrypter decrypter = new KmsDefaultDecrypter(kmsClient, encryptionKeyId);
        parsedJwe.decrypt(decrypter);

        assertThat(payload).isEqualTo(parsedJwe.getPayload().toString());
    }

    @Test
    void testAsymmetricSignerSignsRawMessageSuccessfully() throws Exception {
        KmsClient kmsClient = KmsClient.builder().region(Region.EU_WEST_1).build();
        String payload = "Hello, live KMS! This is a longer message that we've signed.";

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS512).keyID(signingKeyId).build();
        JWSObject jwsObject = new JWSObject(header, new Payload(payload));

        KmsAsymmetricSigner signer = new KmsAsymmetricSigner(kmsClient, signingKeyId, MessageType.RAW);

        jwsObject.sign(signer);

        KmsAsymmetricVerifier verifier = new KmsAsymmetricVerifier(kmsClient, signingKeyId, MessageType.RAW);

        boolean isValid = jwsObject.verify(verifier);

        assertThat(isValid).isTrue();
    }
}
