package com.nimbusds.jose.aws.kms.crypto;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.impl.AAD;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import software.amazon.awssdk.services.kms.KmsClient;

import java.util.Collections;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Live integration test for AWS KMS.
 * To run this test, set the following environment variables:
 * - KMS_KEY_ID: ARN or alias of a KMS key to use for testing.
 * - AWS_REGION: (optional) AWS region to use.
 * - AWS_ACCESS_KEY_ID: (optional) if not using default profile.
 * - AWS_SECRET_ACCESS_KEY: (optional) if not using default profile.
 */
@Tag("LiveIntegration")
public class KmsLiveIntegrationTest {

    private static final String KEY_ID = System.getenv("KMS_KEY_ID");

    @Test
    @EnabledIfEnvironmentVariable(named = "KMS_KEY_ID", matches = ".+")
    public void testDefaultEncrypterDecrypterWithLiveKms() throws Exception {
        KmsClient kmsClient = KmsClient.create();
        String payload = "Hello, live KMS!";
        
        // 1. Encrypt
        JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
                .keyID(KEY_ID)
                .build();
        JWEObject jweObject = new JWEObject(header, new Payload(payload));
        
        KmsDefaultEncrypter encrypter = new KmsDefaultEncrypter(kmsClient, KEY_ID);
        jweObject.encrypt(encrypter);
        String serialized = jweObject.serialize();
        
        // 2. Decrypt
        JWEObject parsedJwe = JWEObject.parse(serialized);
        KmsDefaultDecrypter decrypter = new KmsDefaultDecrypter(kmsClient, KEY_ID);
        parsedJwe.decrypt(decrypter);
        
        assertEquals(payload, parsedJwe.getPayload().toString());
    }

    @Test
    @EnabledIfEnvironmentVariable(named = "KMS_KEY_ID", matches = ".+")
    public void testSymmetricEncrypterDecrypterWithLiveKms() throws Exception {
        KmsClient kmsClient = KmsClient.create();
        String payload = "Hello, live symmetric KMS!";
        
        // 1. Encrypt
        JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.parse("SYMMETRIC_DEFAULT"), EncryptionMethod.A256GCM)
                .keyID(KEY_ID)
                .build();
        JWEObject jweObject = new JWEObject(header, new Payload(payload));
        
        KmsSymmetricEncrypter encrypter = new KmsSymmetricEncrypter(kmsClient, KEY_ID);
        jweObject.encrypt(encrypter);
        String serialized = jweObject.serialize();
        
        // 2. Decrypt
        JWEObject parsedJwe = JWEObject.parse(serialized);
        KmsSymmetricDecrypter decrypter = new KmsSymmetricDecrypter(kmsClient, KEY_ID);
        parsedJwe.decrypt(decrypter);
        
        assertEquals(payload, parsedJwe.getPayload().toString());
    }

    @Test
    @EnabledIfEnvironmentVariable(named = "KMS_KEY_ID", matches = ".+")
    public void testLiveKmsWithAad() throws Exception {
        KmsClient kmsClient = KmsClient.create();
        byte[] cleartext = "Confidential data with AAD".getBytes();
        byte[] aad = "Additional authenticated data".getBytes();
        
        // Use KmsDefaultEncrypter as it supports AAD explicitly
        JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
                .keyID(KEY_ID)
                .build();
        
        KmsDefaultEncrypter encrypter = new KmsDefaultEncrypter(kmsClient, KEY_ID);
        JWECryptoParts parts = encrypter.encrypt(header, cleartext, aad);
        
        KmsDefaultDecrypter decrypter = new KmsDefaultDecrypter(kmsClient, KEY_ID);
        byte[] decrypted = decrypter.decrypt(header, parts.getEncryptedKey(), parts.getInitializationVector(), parts.getCipherText(), parts.getAuthenticationTag(), aad);
        
        assertArrayEquals(cleartext, decrypted);
    }

    @Test
    @EnabledIfEnvironmentVariable(named = "KMS_KEY_ID", matches = ".+")
    public void testLiveKmsWithUserContextAndAad() throws Exception {
        KmsClient kmsClient = KmsClient.create();
        byte[] cleartext = "Data with context and AAD".getBytes();
        byte[] aad = "Some AAD".getBytes();
        Map<String, String> userContext = Collections.singletonMap("app", "test-suite");
        
        JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
                .keyID(KEY_ID)
                .build();
        
        KmsDefaultEncrypter encrypter = new KmsDefaultEncrypter(kmsClient, KEY_ID, userContext);
        JWECryptoParts parts = encrypter.encrypt(header, cleartext, aad);
        
        KmsDefaultDecrypter decrypter = new KmsDefaultDecrypter(kmsClient, KEY_ID, userContext);
        byte[] decrypted = decrypter.decrypt(header, parts.getEncryptedKey(), parts.getInitializationVector(), parts.getCipherText(), parts.getAuthenticationTag(), aad);
        
        assertArrayEquals(cleartext, decrypted);
    }
}
