###############################################################################
#
# Copyright IBM Corp. 2023, 2025
#
# This code is free software; you can redistribute it and/or modify it
# under the terms provided by IBM in the LICENSE file that accompanied
# this code, including the "Classpath" Exception described therein.
###############################################################################

TOPDIR=../../..

PLAT=x86
CC=gcc
CFLAGS= -fPIC
LDFLAGS= -shared
AIX_LIBPATH = /usr/lib:/lib

ifeq (${PLATFORM},arm-linux64)
  PLAT=xr
  CFLAGS+= -DLINUX -Werror -std=gnu99 -pedantic -Wall -fstack-protector
  LDFLAGS+= -DLINUX
  OSINCLUDEDIR=linux
else ifeq (${PLATFORM},ppc-aix64)
  PLAT=ap
  CC=xlc
  CFLAGS= -qcpluscmt -q64 -qpic -DAIX -qhalt=w
  LDFLAGS= -G -q64 -blibpath:${AIX_LIBPATH}
  OSINCLUDEDIR=aix
else ifeq (${PLATFORM},ppcle-linux64)
  PLAT=xl
  CFLAGS+= -DLINUX -Werror
  LDFLAGS+= -m64
  OSINCLUDEDIR=linux
else ifeq (${PLATFORM},s390-linux64)
  PLAT=xz
  LDFLAGS+= -m64
  CFLAGS+= -DS390_PLATFORM -DLINUX -Werror
  OSINCLUDEDIR=linux
else ifeq (${PLATFORM},s390-zos64)
  CC=ibm-clang64
  PLAT=mz
  CFLAGS= -DS390

  # Open XL implies strict
  # https://www.ibm.com/docs/en/open-xl-c-cpp-zos/1.1?topic=options-qstrict
  # HGPR options seems unnecessary for 64-bit environment
  # HOT option not supported
  CFLAGS+= -O3
  CFLAGS+= -fvisibility=default
  CFLAGS+= -fstack-protector-strong
  LDFLAGS= -Wl,-bAMODE=64
  ICCARCHIVE = $(GSKIT_HOME)/libjgsk8iccs_64.x
  OSINCLUDEDIR=zos
else ifeq (${PLATFORM},x86-linux64)
  PLAT=xa
  CFLAGS+= -DLINUX -Werror -std=gnu99 -pedantic -Wall -fstack-protector
  LDFLAGS+= -m64
  OSINCLUDEDIR=linux
endif

#Setting this flag will result non key material such as handle to OCK Objects etc being logged to the trace file.
#This flag must be disabled before building production version
#DEBUG_FLAGS += -DDEBUG
#DEBUG_DETAIL = -DDEBUG_RANDOM_DETAIL -DDEBUG_RAND_DETAIL -DDEBUG_DH_DETAIL -DDEBUG_DSA_DETAIL -DDEBUG_DIGEST_DETAIL -DDEBUG_EC_DETAIL -DDEBUG_EXTENDED_RANDOM_DETAIL -DDEBUG_GCM_DETAIL -DDEBUG_CCM_DETAIL -DDEBUG_HMAC_DETAIL -DDEBUG_PKEY_DETAIL -DDEBUG_CIPHER_DETAIL -DDEBUG_RSA_DETAIL -DDEBUG_SIGNATURE_DETAIL -DDEBUG_SIGNATURE_DSANONE_DETAIL -DDEBUG_SIGNATURE_RSASSL_DETAIL -DDEBUG_HKDF_DETAIL -DDEBUG_RSAPSS_DETAIL -DDEBUG_SIGNATURE_EDDSA_DETAIL -DDEBUG_PBKDF_DETAIL -DDEBUG_PQC_KEY_DETAIL

#Setting this flag will result sensitive key material such as private/public key bytes/parameter bytes being logged to the trace file.
#Please warn the customer know that it not suitable to deploy jgskit library on production system, enabling this flag.
#This flag must be disabled before building production version
#DEBUG_DATA = -DDEBUG_DH_DATA -DDEBUG_DSA_DATA -DDEBUG_EC_DATA -DDEBUG_GCM_DATA -DDEBUG_CCM_DATA -DDEBUG_HMAC_DATA -DDEBUG_CIPHER_DATA -DDEBUG_RSA_DATA -DDEBUG_SIGNATURE_DATA -DDEBUG_SIGNATURE_DSANONE_DATA -DDEBUG_SIGNATURE_RSASSL_DATA -DDEBUG_HKDF_DATA -DDEBUG_RSAPSS_DATA -DDEBUG_SIGNATURE_EDDSA_DATA
#DEBUG_FLAGS+= -g ${DEBUG_DETAIL} ${DEBUG_DATA}

BUILDTOP = ${TOPDIR}/target
HOSTOUT = ${BUILDTOP}/jgskit-${PLAT}-64

OPENJCEPLUS_HEADER_FILES ?= ${TOPDIR}/src/main/native
JAVACLASSDIR=${BUILDTOP}/classes

OBJS = \
	${HOSTOUT}/BasicRandom.o \
	${HOSTOUT}/BuildDate.o \
	${HOSTOUT}/CCM.o \
	${HOSTOUT}/Digest.o \
	${HOSTOUT}/DHKey.o \
	${HOSTOUT}/DSAKey.o \
	${HOSTOUT}/ECKey.o \
	${HOSTOUT}/ExtendedRandom.o \
	${HOSTOUT}/GCM.o \
	${HOSTOUT}/HKDF.o \
	${HOSTOUT}/HMAC.o \
	${HOSTOUT}/KEM.o \
	${HOSTOUT}/MLKey.o \
	${HOSTOUT}/PBKDF.o \
	${HOSTOUT}/PKey.o \
	${HOSTOUT}/Poly1305Cipher.o \
	${HOSTOUT}/RSA.o \
	${HOSTOUT}/RSAKey.o \
	${HOSTOUT}/RsaPss.o \
	${HOSTOUT}/Signature.o \
	${HOSTOUT}/SignatureDSANONE.o \
	${HOSTOUT}/SignatureEdDSA.o \
	${HOSTOUT}/SignaturePQC.o \
	${HOSTOUT}/SignatureRSASSL.o \
	${HOSTOUT}/StaticStub.o \
	${HOSTOUT}/SymmetricCipher.o \
	${HOSTOUT}/Utils.o

TARGET = ${HOSTOUT}/libjgskit.so

GSK8ICCS64=jgsk8iccs_64

all : ${TARGET}

ifneq (,$(filter s390-zos64,${PLATFORM}))
  TARGET_LIBS := ${ICCARCHIVE}
else
  TARGET_LIBS := -L ${GSKIT_HOME}/lib64 -l ${GSK8ICCS64}
endif

${TARGET} : ${OBJS}
	${CC} ${LDFLAGS} -o ${TARGET} ${OBJS} ${TARGET_LIBS}

${HOSTOUT}/%.o : %.c
	test -d ${@D} || mkdir -p ${@D}
	${CC} \
		${CFLAGS} \
		${DEBUG_FLAGS} \
		-c \
		-I${GSKIT_HOME}/inc \
		-I${JAVA_HOME}/include \
		-I${JAVA_HOME}/include/${OSINCLUDEDIR} \
		-I${OPENJCEPLUS_HEADER_FILES} \
		-o $@ \
		$<

# Force BuildDate to be compiled every time.
#
${HOSTOUT}/BuildDate.o : FORCE

FORCE :

ifneq (${EXTERNAL_HEADERS},true)

${OBJS} : | headers

headers :
	echo "Compiling OpenJCEPlus headers"
	${JAVA_HOME}/bin/javac \
		--add-exports java.base/sun.security.util=openjceplus \
		--add-exports java.base/sun.security.util=ALL-UNNAMED \
		-d ${JAVACLASSDIR} \
		-h ${TOPDIR}/src/main/native/ \
		${TOPDIR}/src/main/java/com/ibm/crypto/plus/provider/ock/FastJNIBuffer.java \
		${TOPDIR}/src/main/java/com/ibm/crypto/plus/provider/ock/NativeInterface.java

endif # ! EXTERNAL_HEADERS

clean :
	rm -f ${HOSTOUT}/*.o
	rm -f ${HOSTOUT}/*.so
	rm -f com_ibm_crypto_plus_provider_ock_FastJNIBuffer.h
	rm -f com_ibm_crypto_plus_provider_ock_NativeInterface.h

.PHONY : all headers clean FORCE
