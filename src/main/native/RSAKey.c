/*
 * Copyright IBM Corp. 2023
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <jcc_a.h>
#include <icc.h>

#include "com_ibm_crypto_plus_provider_ock_NativeInterface.h"
#include "Utils.h"
#include <stdint.h>
#include <pthread.h>

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    RSAKEY_generate
 * Signature: (JI)J
 */

/* Sequence number for correlating calls */
static volatile unsigned long g_seq = 0;
static unsigned long next_seq(void) {
    return __sync_add_and_fetch(&g_seq, 1);
}

static unsigned long get_tid(void) {
    return (unsigned long)pthread_self();
}

/*
 * Optional: if your ICC headers expose a status query, you can enable this.
 * We do NOT assume the function exists; we guard it with macros so builds don't break.
 *
 * To enable, define ICC_HAVE_GET_STATUS at compile time and include the right header(s),
 * and make sure ICC_STATUS is a concrete struct (not opaque).
 *
 * Example (only if it exists in your ICC):
 *   int ICC_GetStatus(ICC_CTX *ctx, ICC_STATUS *st);
 */
static void dump_icc_ctx_info(ICC_CTX *ockCtx,
                              jlong ockContextId,
                              unsigned long tid,
                              unsigned long seq,
                              jint numBits,
                              jlong e) {

    /* Print pointer + numeric value so it matches Java's decimal prints */
    fprintf(stderr,
        "[NATIVE][tid=%lu][seq=%lu] ctx=%p ctxId(dec)=%ld javaCtxId(dec)=%ld numBits=%d e=%ld\n",
        tid, seq,
        (void*)ockCtx,
        (long)(intptr_t)ockCtx,          /* pointer value as decimal */
        (long)ockContextId,              /* value passed from Java */
        (int)numBits,
        (long)e
    );
    fflush(stderr);

#ifdef ICC_HAVE_GET_STATUS
    /* If available in your ICC headers, dump ICC_STATUS here */
    ICC_STATUS st;
    memset(&st, 0, sizeof(st));

    int rc = ICC_GetStatus(ockCtx, &st);
    fprintf(stderr,
        "[NATIVE][tid=%lu][seq=%lu] ICC_GetStatus rc=%d\n",
        tid, seq, rc
    );

    /* TODO: print st fields here once you paste ICC_STATUS_t definition */
    /* Example (fake fields): fprintf(stderr, "  fips=%d\n", st.fips_mode); */

    fflush(stderr);
#endif

#ifdef ICC_HAVE_GET_VERSION
    /* If available, print ICC version/build strings */
    const char *ver = ICC_GetVersionString(); /* name may differ */
    fprintf(stderr,
        "[NATIVE][tid=%lu][seq=%lu] ICC version: %s\n",
        tid, seq, (ver != NULL) ? ver : "<null>"
    );
    fflush(stderr);
#endif
}

static void dump_icc_errors(ICC_CTX *ockCtx, unsigned long tid, unsigned long seq) {
    unsigned long errCode;
    int idx = 0;

    while ((errCode = ICC_ERR_get_error(ockCtx)) != 0) {
        idx++;
        char *errStr = ICC_ERR_error_string(ockCtx, errCode, NULL);
        fprintf(stderr,
            "[NATIVE][tid=%lu][seq=%lu] ICC error #%d: code=%lu (0x%lx) str=%s\n",
            tid, seq, idx, errCode, errCode,
            (errStr != NULL) ? errStr : "<null>");
    }

    if (idx == 0) {
        fprintf(stderr,
            "[NATIVE][tid=%lu][seq=%lu] ICC error queue empty\n",
            tid, seq);
    }
    fflush(stderr);
}

JNIEXPORT jlong JNICALL
Java_com_ibm_crypto_plus_provider_ock_NativeInterface_RSAKEY_1generate(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jint numBits, jlong e) {

    ICC_CTX *ockCtx = (ICC_CTX *)((intptr_t)ockContextId);
    ICC_RSA *ockRSA = NULL;

    unsigned long tid = get_tid();
    unsigned long seq = next_seq();

    /* Low-impact: only print this every so often, OR only on failure.
       For now, print only on failure to reduce timing changes. */

    ockRSA = ICC_RSA_generate_key(ockCtx, (int)numBits, (long)e, NULL, NULL);
    if (ockRSA == NULL) {
        fprintf(stderr,
            "[NATIVE][tid=%lu][seq=%lu] RSAKEY_generate FAIL\n",
            tid, seq
        );
        fflush(stderr);

        /* Print more context about the ctx + inputs */
        dump_icc_ctx_info(ockCtx, ockContextId, tid, seq, numBits, e);

        /* Drain ICC error queue */
        dump_icc_errors(ockCtx, tid, seq);

        throwOCKException(env, 0, "ICC_RSA_generate_key() failed");
        return 0;
    }

    return (jlong)((intptr_t)ockRSA);
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    RSAKEY_createPrivateKey
 * Signature: (J[B)J
 */
JNIEXPORT jlong JNICALL
Java_com_ibm_crypto_plus_provider_ock_NativeInterface_RSAKEY_1createPrivateKey(
    JNIEnv *env, jclass thisObj, jlong ockContextId,
    jbyteArray privateKeyBytes) {
    static const char *functionName = "NativeInterface.RSAKEY_createPrivateKey";

    ICC_CTX             *ockCtx         = (ICC_CTX *)((intptr_t)ockContextId);
    ICC_RSA             *ockRSA         = NULL;
    ICC_EVP_PKEY        *ockPKey        = NULL;
    unsigned char       *keyBytesNative = NULL;
    jboolean             isCopy         = 0;
    jlong                rsaKeyId       = 0;
    const unsigned char *pBytes         = NULL;
    jint                 size           = 0;

    if (debug) {
        gslogFunctionEntry(functionName);
    }

    if (privateKeyBytes == NULL) {
        throwOCKException(env, 0,
                          "The RSA Key Private Key bytes are incorrect.");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return rsaKeyId;
    }
    keyBytesNative = (unsigned char *)((*env)->GetPrimitiveArrayCritical(
        env, privateKeyBytes, &isCopy));
    if (NULL == keyBytesNative) {
#ifdef DEBUG_RSA_DETAIL
        if (debug) {
            gslogMessage("DETAIL_RSA  FAILURE keyBytesNative");
        }
#endif
        throwOCKException(env, 0, "NULL from GetPrimitiveArrayCritical!");
    } else {
        if (debug) {
            gslogMessage("DETAIL_RSA KeyBytesNative allocated");
        }
        //  unsigned char * pBytes = (unsigned char *)keyBytesNative;
        pBytes = (const unsigned char *)keyBytesNative;
        //  jint size = (*env)->GetArrayLength(env, privateKeyBytes);
        size = (*env)->GetArrayLength(env, privateKeyBytes);
#ifdef DEBUG_RSA_DATA
        if (debug) {
            gslogMessagePrefix("DATA_RSA Private KeyBytes : ");
            gslogMessageHex((char *)pBytes, 0, (int)size, 0, 0, NULL);
        }
#endif

        ockPKey = ICC_EVP_PKEY_new(ockCtx);
        if (NULL == ockPKey) {
            ockCheckStatus(ockCtx);
#ifdef DEBUG_RSA_DETAIL
            if (debug) {
                gslogMessage("DETAIL_RSA  FAILURE ICC_EVP_PKEY_new ");
            }
#endif
            throwOCKException(env, 0, "ICC_EVP_PKEY_new failed");
        } else {
            ICC_EVP_PKEY *ret =
                ICC_d2i_PrivateKey(ockCtx, 6, &ockPKey, &pBytes, (long)size);
#ifdef DEBUG_RSA_DETAIL
            if (debug) {
                gslogMessage("DETAIL_RSA pointer to ICC_EVP_PKEY %x", ret);
            }
#endif
            if (ret == NULL) {
                ockCheckStatus(ockCtx);
#ifdef DEBUG_RSA_DETAIL
                if (debug) {
                    gslogMessage("DETAIL_RSA  FAILURE ICC_d2i_PrivateKey");
                }
#endif
                throwOCKException(env, 0, "ICC_d2i_PrivateKey failed");
            } else {
                ockRSA = ICC_EVP_PKEY_get1_RSA(ockCtx, ockPKey);
                if (ockRSA == NULL) {
#ifdef DEBUG_RSA_DETAIL
                    if (debug) {
                        gslogMessage(
                            "DETAIL_RSA  FAILURE ICC_EVP_PKEY_get1_RSA");
                    }
#endif
                    ockCheckStatus(ockCtx);
                    throwOCKException(env, 0, "ICC_EVP_PKEY_get1_RSA failed");
                } else {
                    rsaKeyId = (jlong)((intptr_t)ockRSA);
#ifdef DEBUG_RSA_DETAIL
                    if (debug) {
                        gslogMessage("DETAIL_RSA  rsaKeyId %lx", rsaKeyId);
                    }
#endif
                }
            }
        }
    }

    if (keyBytesNative != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, privateKeyBytes,
                                              keyBytesNative, 0);
    }

    if (ockPKey != NULL) {
        ICC_EVP_PKEY_free(ockCtx, ockPKey);
        ockPKey = NULL;
    }

    if (debug) {
        gslogFunctionExit(functionName);
    }

    return rsaKeyId;
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    RSAKEY_createPublicKey
 * Signature: (J[B)J
 */
JNIEXPORT jlong JNICALL
Java_com_ibm_crypto_plus_provider_ock_NativeInterface_RSAKEY_1createPublicKey(
    JNIEnv *env, jclass thisObj, jlong ockContextId,
    jbyteArray publicKeyBytes) {
    static const char *functionName = "NativeInterface.RSAKEY_createPublicKey";

    ICC_CTX             *ockCtx         = (ICC_CTX *)((intptr_t)ockContextId);
    ICC_RSA             *ockRSA         = NULL;
    ICC_EVP_PKEY        *ockPKey        = NULL;
    unsigned char       *keyBytesNative = NULL;
    jboolean             isCopy         = 0;
    jlong                rsaKeyId       = 0;
    const unsigned char *pBytes         = NULL;
    jint                 size           = 0;

    if (debug) {
        gslogFunctionEntry(functionName);
    }
    if (publicKeyBytes == NULL) {
        throwOCKException(env, 0, "The RSA Key Public bytes are incorrect.");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return rsaKeyId;
    }
    keyBytesNative = (unsigned char *)((*env)->GetPrimitiveArrayCritical(
        env, publicKeyBytes, &isCopy));
    if (NULL == keyBytesNative) {
#ifdef DEBUG_RSA_DETAIL
        if (debug) {
            gslogMessage("DETAIL_RSA  FAILURE keyBytesNative");
        }
#endif
        throwOCKException(env, 0, "NULL from GetPrimitiveArrayCritical!");
    } else {
#ifdef DEBUG_RSA_DETAIL
        if (debug) {
            gslogMessage("DETAIL_RSA KeyBytesNative allocated");
        }
#endif
        pBytes = (const unsigned char *)keyBytesNative;
        size   = (*env)->GetArrayLength(env, publicKeyBytes);
#ifdef DEBUG_RSA_DATA
        if (debug) {
            gslogMessagePrefix("DATA_RSA PublicKeyBytes : ");
            gslogMessageHex((char *)pBytes, 0, (int)size, 0, 0, NULL);
        }
#endif

        ockPKey = ICC_EVP_PKEY_new(ockCtx);
        if (NULL == ockPKey) {
            ockCheckStatus(ockCtx);
#ifdef DEBUG_RSA_DETAIL
            if (debug) {
                gslogMessage("DETAIL_RSA  FAILURE ICC_EVP_PKEY_new");
            }
#endif
            throwOCKException(env, 0, "ICC_EVP_PKEY_new failed");
        } else {
            ICC_EVP_PKEY *ret = ICC_d2i_PublicKey(ockCtx, ICC_EVP_PKEY_RSA,
                                                  &ockPKey, &pBytes, (int)size);
#ifdef DEBUG_RSA_DETAIL
            if (debug) {
                gslogMessage("DETAIL_RSA ICC_EVP_PKEY  %x", ret);
            }
#endif
            if (ret == NULL) {
#ifdef DEBUG_RSA_DETAIL
                if (debug) {
                    gslogMessage("DETAIL_RSA  FAILURE ICC_d2i_PublicKey");
                }
#endif
                ockCheckStatus(ockCtx);
                throwOCKException(env, 0, "ICC_d2i_PublicKey failed");
            } else {
                ockRSA = ICC_EVP_PKEY_get1_RSA(ockCtx, ockPKey);
                if (ockRSA == NULL) {
#ifdef DEBUG_RSA_DETAIL
                    if (debug) {
                        gslogMessage(
                            "DETAIL_RSA  FAILURE ICC_EVP_PKEY_get1_RSA");
                    }
#endif
                    ockCheckStatus(ockCtx);
                    throwOCKException(env, 0, "ICC_EVP_PKEY_get1_RSA failed");
                } else {
                    rsaKeyId = (jlong)((intptr_t)ockRSA);
#ifdef DEBUG_RSA_DETAIL
                    if (debug) {
                        gslogMessage("DETAIL_RSA rsaKeyId  %lx",
                                     (long)rsaKeyId);
                    }
#endif
                }
            }
        }
    }

    if (keyBytesNative != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, publicKeyBytes,
                                              keyBytesNative, 0);
    }

    if (ockPKey != NULL) {
        ICC_EVP_PKEY_free(ockCtx, ockPKey);
        ockPKey = NULL;
    }

    if (debug) {
        gslogFunctionExit(functionName);
    }

    return rsaKeyId;
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    RSAKEY_getPrivateKeyBytes
 * Signature: (JJ)[B
 */
JNIEXPORT jbyteArray JNICALL
Java_com_ibm_crypto_plus_provider_ock_NativeInterface_RSAKEY_1getPrivateKeyBytes(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jlong rsaKeyId) {
    static const char *functionName =
        "NativeInterface.RSAKEY_getPrivateKeyBytes";

    ICC_CTX       *ockCtx         = (ICC_CTX *)((intptr_t)ockContextId);
    ICC_RSA       *ockRSA         = (ICC_RSA *)((intptr_t)rsaKeyId);
    jbyteArray     keyBytes       = NULL;
    unsigned char *keyBytesNative = NULL;
    jboolean       isCopy         = 0;
    int            size;
    jbyteArray     retKeyBytes = NULL;

    if (debug) {
        gslogFunctionEntry(functionName);
    }

    if (ockRSA == NULL) {
        throwOCKException(env, 0, "The RSA Key identifier is incorrect.");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return retKeyBytes;
    }

#ifdef DEBUG_RSA_DETAIL
    if (debug) {
        gslogMessage("DETAIL_RSA rsaKeyId  %lx", (long)rsaKeyId);
    }
#endif
    size = ICC_i2d_RSAPrivateKey(ockCtx, ockRSA, NULL);
    if (size <= 0) {
#ifdef DEBUG_RSA_DETAIL
        if (debug) {
            gslogMessage("DETAIL_RSA  FAILURE ICC_i2d_RSAPrivateKey");
        }
#endif
        ockCheckStatus(ockCtx);
        throwOCKException(env, 0, "ICC_i2d_RSAPrivateKey failed");
    } else {
        keyBytes = (*env)->NewByteArray(env, size);
        if (keyBytes == NULL) {
#ifdef DEBUG_RSA_DETAIL
            if (debug) {
                gslogMessage("DETAIL_RSA  FAILURE keyBytes");
            }
#endif
            throwOCKException(env, 0, "NewByteArray failed");
        } else {
            keyBytesNative =
                (unsigned char *)((*env)->GetPrimitiveArrayCritical(
                    env, keyBytes, &isCopy));
            if (keyBytesNative == NULL) {
#ifdef DEBUG_RSA_DETAIL
                if (debug) {
                    gslogMessage("DETAIL_RSA  FAILURE keyBytesNative ");
                }
#endif
                throwOCKException(env, 0,
                                  "NULL from GetPrimitiveArrayCritical");
            } else {
                unsigned char *pBytes = (unsigned char *)keyBytesNative;

                size = ICC_i2d_RSAPrivateKey(ockCtx, ockRSA, &pBytes);
                if (size <= 0) {
                    ockCheckStatus(ockCtx);
#ifdef DEBUG_RSA_DETAIL
                    if (debug) {
                        gslogMessage(
                            "DETAIL_RSA  FAILURE ICC_i2d_RSAPrivateKey");
                    }
#endif
                    throwOCKException(env, 0, "ICC_i2d_RSAPrivateKey failed");
                } else {
                    retKeyBytes = keyBytes;
#ifdef DEBUG_RSA_DATA
                    if (debug) {
                        gslogMessagePrefix("DATA_RSA private KeyBytes : ");
                        gslogMessageHex((char *)pBytes, 0, (int)size, 0, 0,
                                        NULL);
                    }
#endif
                }
            }
        }
    }

    if (keyBytesNative != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, keyBytes, keyBytesNative, 0);
    }

    if ((keyBytes != NULL) && (retKeyBytes == NULL)) {
        (*env)->DeleteLocalRef(env, keyBytes);
    }

    if (debug) {
        gslogFunctionExit(functionName);
    }

    return retKeyBytes;
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    RSAKEY_getPublicKeyBytes
 * Signature: (JJ)[B
 */
JNIEXPORT jbyteArray JNICALL
Java_com_ibm_crypto_plus_provider_ock_NativeInterface_RSAKEY_1getPublicKeyBytes(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jlong rsaKeyId) {
    static const char *functionName =
        "NativeInterface.RSAKEY_getPublicKeyBytes";

    ICC_CTX       *ockCtx         = (ICC_CTX *)((intptr_t)ockContextId);
    ICC_RSA       *ockRSA         = (ICC_RSA *)((intptr_t)rsaKeyId);
    jbyteArray     keyBytes       = NULL;
    unsigned char *keyBytesNative = NULL;
    jboolean       isCopy         = 0;
    int            size;
    jbyteArray     retKeyBytes = NULL;

    if (debug) {
        gslogFunctionEntry(functionName);
    }

    if (ockRSA == NULL) {
        throwOCKException(env, 0, "The RSA Key identifier is incorrect.");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return retKeyBytes;
    }
    size = ICC_i2d_RSAPublicKey(ockCtx, ockRSA, NULL);
#ifdef DEBUG_RSA_DETAIL
    if (debug) {
        gslogMessage("DETAIL_RSA rsaKeyId %lx size %d ", (long)rsaKeyId,
                     (int)size);
    }
#endif
    if (size <= 0) {
#ifdef DEBUG_RSA_DETAIL
        if (debug) {
            gslogMessage("DETAIL_RSA  FAILURE ICC_i2d_RSAPublicKey");
        }
#endif
        ockCheckStatus(ockCtx);
        throwOCKException(env, 0, "ICC_i2d_RSAPublicKey failed");
    } else {
        keyBytes = (*env)->NewByteArray(env, size);
        if (keyBytes == NULL) {
#ifdef DEBUG_RSA_DETAIL
            if (debug) {
                gslogMessage("DETAIL_RSA  FAILURE keyBytes ");
            }
#endif
            throwOCKException(env, 0, "NewByteArray failed");
        } else {
            keyBytesNative =
                (unsigned char *)((*env)->GetPrimitiveArrayCritical(
                    env, keyBytes, &isCopy));
            if (keyBytesNative == NULL) {
#ifdef DEBUG_RSA_DETAIL
                if (debug) {
                    gslogMessage("DETAIL_RSA  FAILURE keyBytesNative ");
                }
#endif
                throwOCKException(env, 0,
                                  "NULL from GetPrimitiveArrayCritical");
            } else {
                unsigned char *pBytes = (unsigned char *)keyBytesNative;

                size = ICC_i2d_RSAPublicKey(ockCtx, ockRSA, &pBytes);
                if (size <= 0) {
                    ockCheckStatus(ockCtx);
#ifdef DEBUG_RSA_DETAIL
                    if (debug) {
                        gslogMessage(
                            "DETAIL_RSA  FAILURE ICC_i2d_RSAPublicKey");
                    }
#endif
                    throwOCKException(env, 0, "ICC_i2d_RSAPublicKey failed");
                } else {
                    retKeyBytes = keyBytes;
#ifdef DEBUG_RSA_DATA
                    if (debug) {
                        gslogMessagePrefix("DATA_RSA KeyBytes : ");
                        gslogMessageHex((char *)pBytes, 0, (int)size, 0, 0,
                                        NULL);
                    }
#endif
                }
            }
        }
    }

    if (keyBytesNative != NULL) {
        (*env)->ReleasePrimitiveArrayCritical(env, keyBytes, keyBytesNative, 0);
    }

    if ((keyBytes != NULL) && (retKeyBytes == NULL)) {
        (*env)->DeleteLocalRef(env, keyBytes);
    }

    if (debug) {
        gslogFunctionExit(functionName);
    }

    return keyBytes;
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    RSAKEY_createPKey
 * Signature: (JJ)J
 */
JNIEXPORT jlong JNICALL
Java_com_ibm_crypto_plus_provider_ock_NativeInterface_RSAKEY_1createPKey(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jlong rsaKeyId) {
    static const char *functionName = "NativeInterface.RSAKEY_createPKey";

    ICC_CTX      *ockCtx  = (ICC_CTX *)((intptr_t)ockContextId);
    ICC_RSA      *ockRSA  = (ICC_RSA *)((intptr_t)rsaKeyId);
    ICC_EVP_PKEY *ockPKey = NULL;
    jlong         pkeyId  = 0;

    if (debug) {
        gslogFunctionEntry(functionName);
    }

    if (ockRSA == NULL) {
        throwOCKException(env, 0, "The RSA Key identifier is incorrect.");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return pkeyId;
    }
#ifdef DEBUG_RSA_DETAIL
    if (debug) {
        gslogMessage("DETAIL_RSA rsaKeyId %lx ", (long)rsaKeyId);
    }
#endif

    ockPKey = ICC_EVP_PKEY_new(ockCtx);
    if (ockPKey == NULL) {
#ifdef DEBUG_RSA_DETAIL
        if (debug) {
            gslogMessage("DETAIL_RSA  FAILURE ICC_EVP_PKEY_new");
        }
#endif
        ockCheckStatus(ockCtx);
        throwOCKException(env, 0, "ICC_EVP_PKEY_new failed");
    } else {
        int rc = ICC_EVP_PKEY_set1_RSA(ockCtx, ockPKey, ockRSA);
#ifdef DEBUG_RSA_DETAIL
        if (debug) {
            gslogMessage("DETAIL_RSA rc from ICC_EVP_PKEY_set1_RSA %d ", rc);
        }
#endif
        if (rc != ICC_OSSL_SUCCESS) {
            ockCheckStatus(ockCtx);
#ifdef DEBUG_RSA_DETAIL
            if (debug) {
                gslogMessage("DETAIL_RSA  FAILURE ICC_EVP_PKEY_set1_RSA %d",
                             rc);
            }
#endif
            throwOCKException(env, 0, "ICC_EVP_PKEY_set1_RSA failed");
        } else {
            pkeyId = (jlong)((intptr_t)ockPKey);
#ifdef DEBUG_RSA_DETAIL
            if (debug) {
                gslogMessage("DETAIL_RSA pkeyId %lx=", pkeyId);
            }
#endif
        }
    }

    if ((ockPKey != NULL) && (pkeyId == 0)) {
        ICC_EVP_PKEY_free(ockCtx, ockPKey);
        ockPKey = NULL;
    }

    if (debug) {
        gslogFunctionExit(functionName);
    }

    return pkeyId;
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    RSAKEY_size
 * Signature: (JJ)I
 */
JNIEXPORT jint JNICALL
Java_com_ibm_crypto_plus_provider_ock_NativeInterface_RSAKEY_1size(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jlong rsaKeyId) {
    static const char *functionName = "NativeInterface.RSAKEY_size";

    ICC_CTX *ockCtx = (ICC_CTX *)((intptr_t)ockContextId);
    ICC_RSA *ockRSA = (ICC_RSA *)((intptr_t)rsaKeyId);
    int      size   = 0;

    if (debug) {
        gslogFunctionEntry(functionName);
    }

    if (ockRSA == NULL) {
        throwOCKException(env, 0, "The RSA Key identifier is incorrect.");
        if (debug) {
            gslogFunctionExit(functionName);
        }
        return size;
    }
#ifdef DEBUG_RSA_DETAIL
    if (debug) {
        gslogMessage("DETAIL_RSA rsaKeyId=%lx", (long)rsaKeyId);
    }
#endif

    size = ICC_RSA_size(ockCtx, ockRSA);
#ifdef DEBUG_RSA_DETAIL
    if (debug) {
        gslogMessage("DETAIL_RSA size=%d", size);
    }
#endif

    if (debug) {
        gslogFunctionExit(functionName);
    }

    return size;
}

//============================================================================
/*
 * Class:     com_ibm_crypto_plus_provider_ock_NativeInterface
 * Method:    RSAKEY_delete
 * Signature: (JJ)V
 */
JNIEXPORT void JNICALL
Java_com_ibm_crypto_plus_provider_ock_NativeInterface_RSAKEY_1delete(
    JNIEnv *env, jclass thisObj, jlong ockContextId, jlong rsaKeyId) {
    static const char *functionName = "NativeInterface.RSAKEY_delete";

    ICC_CTX *ockCtx = (ICC_CTX *)((intptr_t)ockContextId);
    ICC_RSA *ockRSA = (ICC_RSA *)((intptr_t)rsaKeyId);

    if (debug) {
        gslogFunctionEntry(functionName);
    }
#ifdef DEBUG_RSA_DETAIL
    if (debug) {
        gslogMessage("DETAIL_RSA rsaKeyId=%lx", (long)rsaKeyId);
    }
#endif
    if (ockRSA != NULL) {
        ICC_RSA_free(ockCtx, ockRSA);
        ockRSA = NULL;
    }

    if (debug) {
        gslogFunctionExit(functionName);
    }
}
