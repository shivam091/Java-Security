package org.security.crypt.pkcs;

import org.security.crypt.symmetric.AlgorithmSpec;

/**
 * Supported password-based encryption algorithms for PKCS#5 PBES2 encryption
 * scheme. The ciphers mentioned in PKCS#5 are supported as well as others in
 * common use or of presumed value.
 *
 * @author shivam
 * 
 */
public enum PBES2Algorithm {

	/** DES CBC cipher. */
	DES("1.3.14.3.2.7", new AlgorithmSpec("DES", "CBC", "PKCS5Padding"), 64),

	/** 3-DES CBC cipher. */
	DESede("1.2.840.113549.3.7", new AlgorithmSpec("DESede", "CBC",
			"PKCS5Padding"), 192),

	/** RC2 CBC cipher. */
	RC2("1.2.840.113549.3.2", new AlgorithmSpec("RC2", "CBC", "PKCS5Padding"),
			-1),

	/** RC5 CBC cipher. */
	RC5("1.2.840.113549.3.9", new AlgorithmSpec("RC5", "CBC", "PKCS5Padding"),
			-1),

	/** AES-128 CBC cipher. */
	AES128("2.16.840.1.101.3.4.1.2", new AlgorithmSpec("AES", "CBC",
			"PKCS5Padding"), 128),

	/** AES-192 CBC cipher. */
	AES192("2.16.840.1.101.3.4.1.22", new AlgorithmSpec("AES", "CBC",
			"PKCS5Padding"), 192),

	/** AES-256 CBC cipher. */
	AES256("2.16.840.1.101.3.4.1.42", new AlgorithmSpec("AES", "CBC",
			"PKCS5Padding"), 256);

	/** Algorithm identifier OID. */
	private final String oid;

	/** Cipher algorithm specification. */
	private final AlgorithmSpec spec;

	/** Cipher key size in bits. */
	private final int keySize;

	/**
	 * Creates a new instance with given parameters.
	 *
	 * @param id
	 *            Algorithm OID.
	 * @param cipherSpec
	 *            Cipher algorithm specification.
	 * @param keySizeBits
	 *            Size of derived key in bits to be used with cipher.
	 */
	PBES2Algorithm(final String id, final AlgorithmSpec cipherSpec,
			final int keySizeBits) {
		this.oid = id;
		this.spec = cipherSpec;
		this.keySize = keySizeBits;
	}

	/**
	 * Gets the PBE algorithm for the given object identifier.
	 *
	 * @param oid
	 *            PBE algorithm OID.
	 *
	 * @return Algorithm whose identifier equals given value.
	 *
	 * @throws IllegalArgumentException
	 *             If no matching algorithm found.
	 */
	public static PBES2Algorithm fromOid(final String oid) {
		for (PBES2Algorithm a : PBES2Algorithm.values()) {
			if (a.getOid().equals(oid)) {
				return a;
			}
		}
		throw new IllegalArgumentException("Unknown PBES1Algorithm for OID "
				+ oid);
	}

	/** @return the oid */
	public String getOid() {
		return oid;
	}

	/** @return Cipher algorithm specification. */
	public AlgorithmSpec getSpec() {
		return spec;
	}

	/**
	 * @return Size of derived key in bits or -1 if algorithm does not define a
	 *         key size.
	 */
	public int getKeySize() {
		return keySize;
	}
}