# Nimbus JOSE + JWT AWS KMS extension

This library is an updated fork of Amazon's extension of the [nimbus-jose-jwt](https://connect2id.com/products/nimbus-jose-jwt) 
library. It is compatible with version >10.7 of nimbus-jose-jwt. It provides JWE-based encrypters/decrypters and JWS-based
signers/verifiers for doing operations with cryptographic keystores in AWS KMS. This library requires Java 8 or above.

# Usage

In the current version the following encryption and signing operations are supported:

1. Symmetric encryption (AES-based).
    1. Classes: `com.nimbusds.jose.aws.kms.crypto.KmsSymmetricEncrypter`
       and `com.nimbusds.jose.aws.kms.crypto.KmsSymmetricDecrypter`
2. Asymmetric or Symmetric encryption (RSA or ECDSA based for asymmetric keys and AES based for symmetric keys).
    1. Classes: `com.nimbusds.jose.aws.kms.crypto.KmsDefaultEncrypter`
       and `com.nimbusds.jose.aws.kms.crypto.KmsDefaultDecrypter`
3. Asymmetric signing (RSA or ECDSA based).
    1. Classes: `com.nimbusds.jose.aws.kms.crypto.KmsAsymmetricSigner`
       and `com.nimbusds.jose.aws.kms.crypto.KmsAsymmetricVerifier`

The above classes should be used in the same way any encryption or signing class, which is directly provided by
nimbus-jose-jwt, is used.

*Note:* For encryption using symmetric KMS keys, you can use either the `KmsDefaultEncrypter` class or the
`KmsSymmetricEncrypter` class (and similarly can use `KmsDefaultDecrypter` or `KmsSymmetricDecrypter`, for decryption).
The difference between these two classes is that `KmsDefaultEncrypter` generates an in-memory CEK and sends it to KMS
for encryption using KMS's [Encrypt](https://docs.aws.amazon.com/kms/latest/APIReference/API_Encrypt.html) API, while
`KmsSymmetricEncrypter` uses KMS's [GenerateDataKey](https://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateDataKey.html) API to generate the CEK and fetch its plaintext and encrypted 
versions.

## Encryption Example (Java 8)
```jshelllanguage
    try (KmsClient kmsClient = KmsClient.create()) {
      final KmsSymmetricEncrypter jweEncrypter = new KmsSymmetricEncrypter(kmsClient, privateKeyId);
    
      final JWEHeader jweHeader = new JWEHeader.Builder(alg, enc).keyID(privateKeyId).build();
    
      final JWEObject jweObject = new JWEObject(jweHeader, new Payload(payload));
    
      jweObject.encrypt(jweEncrypter);
    }
```

## Signing Example (Java 8)
```jshelllanguage
    try (KmsClient kmsClient = KmsClient.create()) {
      final KmsAsymmetricSigner jwsSigner = new KmsAsymmetricSigner(kmsClient, privateKeyId, MessageType.RAW);
    
      final JWSHeader jwsHeader = new JWSHeader.Builder(alg)
      .keyID(privateKeyId)
      .build();
    
      final JWSObject jwsObject = new JWSObject(jwsHeader, new Payload(payload));
    
      jwsObject.sign(jwsSigner);
    }
```

# Installation

This library is available on [Maven Central](https://search.maven.org/artifact/software.amazon.lynx/nimbus-jose-jwt_aws-kms-extension).
Following are the installation details.

## Apache Maven

```xml
<dependency>
    <groupId>com.joshuaharwood</groupId>
    <artifactId>nimbus-jose-jwt_aws-kms-extension</artifactId>
    <version>2.0.0</version>
</dependency>
```

## Gradle Groovy DSL

```groovy
repositories {
    mavenCentral()
}

dependencies {
    implementation "com.joshuaharwood:nimbus-jose-jwt_aws-kms-extension:2.0.0"
}
```

# Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

# License

This project is licensed under the Apache-2.0 License.
