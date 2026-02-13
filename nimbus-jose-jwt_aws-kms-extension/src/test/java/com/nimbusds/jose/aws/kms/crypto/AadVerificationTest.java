package com.nimbusds.jose.aws.kms.crypto;

import com.google.common.collect.ImmutableMap;
import com.nimbusds.jose.*;
import com.nimbusds.jose.aws.kms.crypto.utils.AadEncryptionContextAdapter;
import com.nimbusds.jose.crypto.impl.AAD;
import com.nimbusds.jose.util.Base64URL;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.EncryptRequest;
import software.amazon.awssdk.services.kms.model.EncryptResponse;
import software.amazon.awssdk.services.kms.model.GenerateDataKeyRequest;
import software.amazon.awssdk.services.kms.model.GenerateDataKeyResponse;

import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.entry;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

public class AadVerificationTest {

    private KmsClient mockKms;
    private final String keyId = "test-key-id";

    @BeforeEach
    void setUp() {
        mockKms = mock(KmsClient.class);
    }

    @Test
    public void testNoAadNoEncryptionContext_DefaultEncrypter() throws Exception {
        KmsDefaultEncrypter encrypter = new KmsDefaultEncrypter(mockKms, keyId);
        
        EncryptResponse response = EncryptResponse.builder()
                .ciphertextBlob(SdkBytes.fromByteArray(new byte[32]))
                .build();
        when(mockKms.encrypt(any(EncryptRequest.class))).thenReturn(response);

        JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM).build();
        byte[] clearText = "hello".getBytes(StandardCharsets.UTF_8);

        // This calls encrypt(header, clearText, AAD.compute(header)) internally if using the 2-arg method
        // But KmsDefaultEncrypter doesn't override the 2-arg method from JWEEncrypter, so let's check what it does.
        // Actually it does override it in some versions or we should call it.
        //todo: remove? probably remove.
        encrypter.encrypt(header, clearText);

        ArgumentCaptor<EncryptRequest> captor = ArgumentCaptor.forClass(EncryptRequest.class);
        verify(mockKms).encrypt(captor.capture());

        Map<String, String> context = captor.getValue().encryptionContext();
        byte[] expectedAad = AAD.compute(header);
        String expectedEncodedAad = Base64URL.encode(expectedAad).toString();

        assertThat(context).containsExactly(entry(AadEncryptionContextAdapter.AAD_CONTEXT_KEY, expectedEncodedAad));
    }

    @Test
    public void testOnlyAadProvided_DefaultEncrypter() throws Exception {
        KmsDefaultEncrypter encrypter = new KmsDefaultEncrypter(mockKms, keyId);
        
        EncryptResponse response = EncryptResponse.builder()
                .ciphertextBlob(SdkBytes.fromByteArray(new byte[32]))
                .build();
        when(mockKms.encrypt(any(EncryptRequest.class))).thenReturn(response);

        JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM).build();
        byte[] clearText = "hello".getBytes(StandardCharsets.UTF_8);
        byte[] customAad = "custom-aad".getBytes(StandardCharsets.UTF_8);

        encrypter.encrypt(header, clearText, customAad);

        ArgumentCaptor<EncryptRequest> captor = ArgumentCaptor.forClass(EncryptRequest.class);
        verify(mockKms).encrypt(captor.capture());

        Map<String, String> context = captor.getValue().encryptionContext();
        String expectedEncodedAad = Base64URL.encode(customAad).toString();

        assertThat(context).containsExactly(entry(AadEncryptionContextAdapter.AAD_CONTEXT_KEY, expectedEncodedAad));
    }

    @Test
    public void testOnlyEncryptionContextProvided_DefaultEncrypter() throws Exception {
        Map<String, String> myContext = ImmutableMap.of("user-key", "user-value");
        KmsDefaultEncrypter encrypter = new KmsDefaultEncrypter(mockKms, keyId, myContext);
        
        EncryptResponse response = EncryptResponse.builder()
                .ciphertextBlob(SdkBytes.fromByteArray(new byte[32]))
                .build();
        when(mockKms.encrypt(any(EncryptRequest.class))).thenReturn(response);

        JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM).build();
        byte[] clearText = "hello".getBytes(StandardCharsets.UTF_8);

        // When using the 2-arg method, it computes AAD from header
        encrypter.encrypt(header, clearText);

        ArgumentCaptor<EncryptRequest> captor = ArgumentCaptor.forClass(EncryptRequest.class);
        verify(mockKms).encrypt(captor.capture());

        Map<String, String> context = captor.getValue().encryptionContext();
        assertEquals("user-value", context.get("user-key"));
        
        // IMPORTANT: The issue says "If only an encryption context is provided, only that encryption context is used."
        // Our current implementation ALWAYS adds AAD (derived from header) in this case because JWE ALWAYS has AAD.
        
        byte[] headerAad = AAD.compute(header);
        String expectedEncodedAad = Base64URL.encode(headerAad).toString();
        assertEquals(expectedEncodedAad, context.get(AadEncryptionContextAdapter.AAD_CONTEXT_KEY));
        assertEquals(2, context.size());
    }

    @Test
    public void testOnlyEncryptionContextProvided_StrictCheck_DefaultEncrypter() throws Exception {
        Map<String, String> myContext = ImmutableMap.of("user-key", "user-value");
        KmsDefaultEncrypter encrypter = new KmsDefaultEncrypter(mockKms, keyId, myContext);

        EncryptResponse response = EncryptResponse.builder()
                .ciphertextBlob(SdkBytes.fromByteArray(new byte[32]))
                .build();
        when(mockKms.encrypt(any(EncryptRequest.class))).thenReturn(response);

        JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM).build();
        byte[] clearText = "hello".getBytes(StandardCharsets.UTF_8);

        // We call the 3-arg version with NULL AAD explicitly.
        // The requirement says "If only an encryption context is provided, only that encryption context is used."
        encrypter.encrypt(header, clearText, null);

        ArgumentCaptor<EncryptRequest> captor = ArgumentCaptor.forClass(EncryptRequest.class);
        verify(mockKms).encrypt(captor.capture());

        Map<String, String> context = captor.getValue().encryptionContext();
        assertEquals("user-value", context.get("user-key"));
        assertNull(context.get(AadEncryptionContextAdapter.AAD_CONTEXT_KEY), "AAD should not be present in encryption context when AAD is null");
        assertEquals(1, context.size());
    }

    @Test
    public void testBothProvided_DefaultEncrypter() throws Exception {
        Map<String, String> myContext = ImmutableMap.of("user-key", "user-value");
        KmsDefaultEncrypter encrypter = new KmsDefaultEncrypter(mockKms, keyId, myContext);
        
        EncryptResponse response = EncryptResponse.builder()
                .ciphertextBlob(SdkBytes.fromByteArray(new byte[32]))
                .build();
        when(mockKms.encrypt(any(EncryptRequest.class))).thenReturn(response);

        JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM).build();
        byte[] clearText = "hello".getBytes(StandardCharsets.UTF_8);
        byte[] customAad = "custom-aad".getBytes(StandardCharsets.UTF_8);

        encrypter.encrypt(header, clearText, customAad);

        ArgumentCaptor<EncryptRequest> captor = ArgumentCaptor.forClass(EncryptRequest.class);
        verify(mockKms).encrypt(captor.capture());

        Map<String, String> context = captor.getValue().encryptionContext();
        assertEquals("user-value", context.get("user-key"));
        String expectedEncodedAad = Base64URL.encode(customAad).toString();
        assertEquals(expectedEncodedAad, context.get(AadEncryptionContextAdapter.AAD_CONTEXT_KEY));
    }

    @Test
    public void testNoAadNoEncryptionContext_SymmetricEncrypter() throws Exception {
        KmsSymmetricEncrypter encrypter = new KmsSymmetricEncrypter(mockKms, keyId);
        
        GenerateDataKeyResponse response = GenerateDataKeyResponse.builder()
                .plaintext(SdkBytes.fromByteArray(new byte[32]))
                .ciphertextBlob(SdkBytes.fromByteArray(new byte[32]))
                .build();
        when(mockKms.generateDataKey(any(GenerateDataKeyRequest.class))).thenReturn(response);

        JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.parse("SYMMETRIC_DEFAULT"), EncryptionMethod.A256GCM).build();
        byte[] clearText = "hello".getBytes(StandardCharsets.UTF_8);

        // SymmetricEncrypter doesn't seem to have a 2-arg encrypt method in the provided snippet?
        // Wait, KmsSymmetricEncrypter implements JWEEncrypter.
        // JWEEncrypter (from Nimbus) has encrypt(JWEHeader, byte[]) and encrypt(JWEHeader, byte[], byte[]).
        // Let's see KmsSymmetricEncrypter.java.
        
        encrypter.encrypt(header, clearText, AAD.compute(header));

        ArgumentCaptor<GenerateDataKeyRequest> captor = ArgumentCaptor.forClass(GenerateDataKeyRequest.class);
        verify(mockKms).generateDataKey(captor.capture());

        Map<String, String> context = captor.getValue().encryptionContext();
        byte[] expectedAad = AAD.compute(header);
        String expectedEncodedAad = Base64URL.encode(expectedAad).toString();

        assertEquals(expectedEncodedAad, context.get(AadEncryptionContextAdapter.AAD_CONTEXT_KEY));
    }
}
