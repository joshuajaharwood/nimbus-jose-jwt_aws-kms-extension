package com.nimbusds.jose.aws.kms.crypto;

import com.nimbusds.jose.*;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.EncryptionAlgorithmSpec;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;

//@Disabled
@Tag("LiveIntegration")
public class KmsLiveIntegrationTest {
    String keyId = "REPLACEME";

    @Test
    void testDefaultEncrypterDecrypterWithLiveKms() throws Exception {
        KmsClient kmsClient = KmsClient.builder().region(Region.EU_WEST_1).build();
        String payload = "Hello, live KMS!";

        //TODO: last thing, make it so aad can't be passed in at kms level for asymmetric encryption
        JWEAlgorithm symmetricDefaultAlgo = JWEAlgorithm.parse(EncryptionAlgorithmSpec.SYMMETRIC_DEFAULT.toString());

        // 1. Encrypt
        JWEHeader header = new JWEHeader.Builder(symmetricDefaultAlgo, EncryptionMethod.A256GCM)
                .keyID(keyId)
                .build();
        JWEObject jweObject = new JWEObject(header, new Payload(payload));

        KmsDefaultEncrypter encrypter = new KmsDefaultEncrypter(kmsClient, keyId);
        jweObject.encrypt(encrypter);
        String serialized = jweObject.serialize();

        // 2. Decrypt
        JWEObject parsedJwe = JWEObject.parse(serialized);
        KmsDefaultDecrypter decrypter = new KmsDefaultDecrypter(kmsClient, keyId);
        parsedJwe.decrypt(decrypter);

        assertThat(payload).isEqualTo(parsedJwe.getPayload().toString());
    }

    @Test
    void testAsymmetricSignerWithLiveKms() throws Exception {

    }
}
