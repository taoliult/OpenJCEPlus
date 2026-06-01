# ICC Native Code Return Code Check Issues

## Summary
This document identifies ICC native function calls in the `src/main/native/ock` folder that do not check return codes, which may cause issues when using incorrect state after failures.

## Critical Issues (High Priority)

### 1. SymmetricCipher.c - Unchecked ICC_EVP_CIPHER_CTX_copy and ICC_EVP_EncryptInit/DecryptInit

**Location:** [`src/main/native/ock/SymmetricCipher.c:526-527`](src/main/native/ock/SymmetricCipher.c:526)
```c
ICC_EVP_CIPHER_CTX_copy(ockCtx, ockCipher->cipherCtx,
                        ockCipher->cached_context);
```
**Issue:** Return code not checked. If copy fails, subsequent operations will use invalid context.

**Location:** [`src/main/native/ock/SymmetricCipher.c:529`](src/main/native/ock/SymmetricCipher.c:529)
```c
ICC_EVP_EncryptInit(ockCtx, ockCipher->cipherCtx, NULL, NULL, NULL);
```
**Issue:** Return code not checked. Initialization failure not detected.

**Location:** [`src/main/native/ock/SymmetricCipher.c:637-638`](src/main/native/ock/SymmetricCipher.c:637)
```c
ICC_EVP_CIPHER_CTX_copy(ockCtx, ockCipher->cipherCtx,
                        ockCipher->cached_context);
```
**Issue:** Same as above - return code not checked.

**Location:** [`src/main/native/ock/SymmetricCipher.c:640`](src/main/native/ock/SymmetricCipher.c:640)
```c
ICC_EVP_EncryptInit(ockCtx, ockCipher->cipherCtx, NULL, NULL, NULL);
```
**Issue:** Return code not checked.

**Location:** [`src/main/native/ock/SymmetricCipher.c:764-765`](src/main/native/ock/SymmetricCipher.c:764)
```c
ICC_EVP_CIPHER_CTX_copy(ockCtx, ockCipher->cipherCtx,
                        ockCipher->cached_context);
```
**Issue:** Return code not checked.

**Location:** [`src/main/native/ock/SymmetricCipher.c:767`](src/main/native/ock/SymmetricCipher.c:767)
```c
ICC_EVP_DecryptInit(ockCtx, ockCipher->cipherCtx, NULL, NULL, NULL);
```
**Issue:** Return code not checked.

**Location:** [`src/main/native/ock/SymmetricCipher.c:873-874`](src/main/native/ock/SymmetricCipher.c:873)
```c
ICC_EVP_CIPHER_CTX_copy(ockCtx, ockCipher->cipherCtx,
                        ockCipher->cached_context);
```
**Issue:** Return code not checked.

**Location:** [`src/main/native/ock/SymmetricCipher.c:876`](src/main/native/ock/SymmetricCipher.c:876)
```c
ICC_EVP_DecryptInit(ockCtx, ockCipher->cipherCtx, NULL, NULL, NULL);
```
**Issue:** Return code not checked.

### 2. HKDF.c - Unchecked ICC_HKDF_Extract

**Location:** [`src/main/native/ock/HKDF.c:225-226`](src/main/native/ock/HKDF.c:225)
```c
ICC_HKDF_Extract(ockCtx, ockHKDF->md, saltNative, (int)saltLen,
                 inKeyNative, (int)inKeyLen, prkLocal, &prkLen);
```
**Issue:** Return code not checked. If extraction fails, `prkLocal` and `prkLen` may contain invalid data that will be used in subsequent operations.

### 3. BasicRandom.c - Unchecked ICC_RAND_seed and ICC_GenerateRandomSeed

**Location:** [`src/main/native/ock/BasicRandom.c:94`](src/main/native/ock/BasicRandom.c:94)
```c
ICC_RAND_seed(ockCtx, seedNative, size);
```
**Issue:** Return code not checked. If seeding fails, RNG may be in invalid state.

**Location:** [`src/main/native/ock/BasicRandom.c:133`](src/main/native/ock/BasicRandom.c:133)
```c
ICC_GenerateRandomSeed(ockCtx, &status, size, seedNative);
```
**Issue:** Return code not checked. Random seed generation failure not detected.

### 4. ECKey.c - Unchecked ICC_EVP_PKEY_get_raw_public_key

**Location:** [`src/main/native/ock/ECKey.c:390`](src/main/native/ock/ECKey.c:390)
```c
ICC_EVP_PKEY_get_raw_public_key(ockCtx, key, NULL, &pub_size);
```
**Issue:** Return code not checked. If this call fails, `pub_size` may be uninitialized or invalid, leading to buffer issues in the next call at line 391.

**Location:** [`src/main/native/ock/ECKey.c:1879`](src/main/native/ock/ECKey.c:1879)
```c
ICC_EVP_PKEY_get_raw_public_key(ockCtx, ockEVPKey, NULL, &size);
```
**Issue:** Return code not checked. If this fails, `size` may be invalid, causing issues when creating byte array at line 1880.

### 5. ECKey.c - Unchecked ICC_d2i_PUBKEY

**Location:** [`src/main/native/ock/ECKey.c:1431`](src/main/native/ock/ECKey.c:1431)
```c
ICC_d2i_PUBKEY(ockCtx, &ockEVPKey, (const unsigned char **)&ptr, size);
```
**Issue:** Return code not checked. If decoding fails, `ockEVPKey` may be NULL or invalid, but code continues to use it.

### 6. DHKey.c - Unchecked ICC_EVP_PKEY_set1_DH

**Location:** [`src/main/native/ock/DHKey.c:698`](src/main/native/ock/DHKey.c:698)
```c
ICC_EVP_PKEY_set1_DH(ockCtx, ockPKey, ockDH);
```
**Issue:** Return code not checked. If setting DH key fails, subsequent `ICC_i2d_PrivateKey` at line 699 may fail or produce invalid output.

**Location:** [`src/main/native/ock/DHKey.c:823`](src/main/native/ock/DHKey.c:823)
```c
ICC_EVP_PKEY_set1_DH(ockCtx, ockPKey, ockDH);
```
**Issue:** Return code not checked. If setting DH key fails, subsequent `ICC_i2d_PUBKEY` at line 824 may fail or produce invalid output.

### 7. ECKey.c - Unchecked ICC_i2d_ECParameters

**Location:** [`src/main/native/ock/ECKey.c:865`](src/main/native/ock/ECKey.c:865)
```c
size = ICC_i2d_ECParameters(ockCtx, ockECKey, &pBytes);
```
**Issue:** While `size` is assigned, there's no check if `size <= 0` before using it, unlike similar patterns elsewhere in the code.

### 8. CCM.c and GCM.c - Unchecked ICC_GetValue

**Location:** [`src/main/native/ock/CCM.c:46`](src/main/native/ock/CCM.c:46)
```c
ICC_GetValue(ctx, &status, ICC_VERSION, buffer, 10);
```
**Issue:** Return code not checked. If getting version fails, buffer may contain invalid data.

**Location:** [`src/main/native/ock/GCM.c:864`](src/main/native/ock/GCM.c:864)
```c
ICC_GetValue(ctx, &status, ICC_VERSION, buffer, 10);
```
**Issue:** Same as above.

## Medium Priority Issues

### 9. Signature.c - Unchecked ICC_RSA_FixEncodingZeros

**Location:** [`src/main/native/ock/Signature.c:107`](src/main/native/ock/Signature.c:107)
```c
ICC_RSA_FixEncodingZeros(ockCtx, rsaKeyPtr, NULL, 0);
```
**Issue:** Return code not checked. While this may be a void function, should verify.

### 10. Multiple files - Unchecked ICC_EVP_MD_CTX_init

**Location:** [`src/main/native/ock/Digest.c:109`](src/main/native/ock/Digest.c:109)
```c
ICC_EVP_MD_CTX_init(ockCtx, ockDigest->mdCtx);
```
**Issue:** Return code not checked. If initialization fails, subsequent digest operations will fail.

**Location:** [`src/main/native/ock/RsaPss.c:72`](src/main/native/ock/RsaPss.c:72), [`178`](src/main/native/ock/RsaPss.c:178), [`553`](src/main/native/ock/RsaPss.c:553), [`697`](src/main/native/ock/RsaPss.c:697)
**Issue:** Multiple instances of unchecked `ICC_EVP_MD_CTX_init`.

### 11. SymmetricCipher.c - Unchecked ICC_EVP_CIPHER_CTX_init

**Location:** [`src/main/native/ock/SymmetricCipher.c:113`](src/main/native/ock/SymmetricCipher.c:113)
```c
ICC_EVP_CIPHER_CTX_init(ockCtx, ockCipher->cipherCtx);
```
**Issue:** Return code not checked.

**Location:** [`src/main/native/ock/Poly1305Cipher.c:88`](src/main/native/ock/Poly1305Cipher.c:88)
```c
ICC_EVP_CIPHER_CTX_init(ockCtx, ockCipher->cipherCtx);
```
**Issue:** Return code not checked.

## Low Priority Issues (Cleanup/Free Functions)

The following are free/cleanup functions where return codes are typically not critical, but should still be checked for completeness:

- Various `ICC_EVP_PKEY_free`, `ICC_EVP_PKEY_CTX_free`, `ICC_EC_KEY_free`, `ICC_DH_free`, `ICC_DSA_free` calls
- Various `ICC_EVP_MD_CTX_free`, `ICC_EVP_CIPHER_CTX_free` calls
- Various `ICC_RNG_CTX_free`, `ICC_CRYPTO_free` calls

These are generally in cleanup sections and failure to free is less critical than failure in operational code.

## Recommendations

1. **Immediate Action Required:** Fix all Critical Issues (items 1-8) as these can lead to:
   - Use of uninitialized or invalid data
   - Silent failures that propagate through the code
   - Security vulnerabilities
   - Incorrect cryptographic operations

2. **Pattern to Follow:** Use the pattern from the fixed `XECKEY_computeECDHSecret` method:
   ```c
   rc = ICC_FUNCTION_CALL(...);
   if (rc != ICC_OSSL_SUCCESS) {
       ockCheckStatus(ockCtx);
       throwOCKException(env, 0, "ICC_FUNCTION_CALL failed");
       goto cleanup;
   }
   ```

3. **For size/length queries:** Check if returned size is valid:
   ```c
   size = ICC_FUNCTION_CALL(...);
   if (size <= 0) {
       ockCheckStatus(ockCtx);
       throwOCKException(env, 0, "ICC_FUNCTION_CALL failed");
       goto cleanup;
   }
   ```

4. **Testing:** After fixes, ensure comprehensive testing of error paths to verify proper error handling.

## Files Requiring Updates

1. [`src/main/native/ock/SymmetricCipher.c`](src/main/native/ock/SymmetricCipher.c) - 8 issues
2. [`src/main/native/ock/HKDF.c`](src/main/native/ock/HKDF.c) - 1 issue
3. [`src/main/native/ock/BasicRandom.c`](src/main/native/ock/BasicRandom.c) - 2 issues
4. [`src/main/native/ock/ECKey.c`](src/main/native/ock/ECKey.c) - 4 issues
5. [`src/main/native/ock/DHKey.c`](src/main/native/ock/DHKey.c) - 2 issues
6. [`src/main/native/ock/CCM.c`](src/main/native/ock/CCM.c) - 1 issue
7. [`src/main/native/ock/GCM.c`](src/main/native/ock/GCM.c) - 1 issue
8. [`src/main/native/ock/Digest.c`](src/main/native/ock/Digest.c) - 1 issue
9. [`src/main/native/ock/RsaPss.c`](src/main/native/ock/RsaPss.c) - 4 issues
10. [`src/main/native/ock/Poly1305Cipher.c`](src/main/native/ock/Poly1305Cipher.c) - 1 issue
11. [`src/main/native/ock/Signature.c`](src/main/native/ock/Signature.c) - 1 issue

**Total Critical Issues Found: 26+**