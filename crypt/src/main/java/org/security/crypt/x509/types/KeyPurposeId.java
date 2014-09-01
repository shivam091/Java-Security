package org.security.crypt.x509.types;

/**
 * Represents the <code>KeyPurposeId</code> type described in section 4.2.1.13
 * of RFC 2459, which is used to indicate extended key usage.
 *
 * @author shivam
 * 
 */
public enum KeyPurposeId {

	/** TLS Web server authentication. */
	ServerAuth("1.3.6.1.5.5.7.3.1"),

	/** TLS Web client authentication. */
	ClientAuth("1.3.6.1.5.5.7.3.2"),

	/** Signing of downloadable executable code. */
	CodeSigning("1.3.6.1.5.5.7.3.3"),

	/** E-mail protection, e.g. signing and/or encryption */
	EmailProtection("1.3.6.1.5.5.7.3.4"),

	/** Binding the hash of an object to a time from an agreed-upon time. */
	TimeStamping("1.3.6.1.5.5.7.3.8"),

	/** Microsoft-specific usage for smart-card-based authentication. */
	SmartCardLogin("1.3.6.1.4.1.311.20.2.2");

	/** Key purpose object identifier. */
	private final String oid;

	/**
	 * Creates a new instance with the given OID.
	 *
	 * @param objectId
	 *            Key purpose OID.
	 */
	KeyPurposeId(final String objectId) {
		oid = objectId;
	}

	/** @return Key purpose object identifier. */
	public String getOid() {
		return oid;
	}

	/**
	 * Gets a key purpose identifier by its OID.
	 *
	 * @param oid
	 *            OID of key identifier to retrieve.
	 *
	 * @return Key purpose ID whose OID matches given value.
	 *
	 * @throws IllegalArgumentException
	 *             If there is no key purpose ID with the given OID.
	 */
	public static KeyPurposeId getByOid(final String oid) {
		for (KeyPurposeId id : values()) {
			if (id.getOid().equals(oid)) {
				return id;
			}
		}
		throw new IllegalArgumentException(
				"No key purpose ID defined with oid " + oid);
	}
}