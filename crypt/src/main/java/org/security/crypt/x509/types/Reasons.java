package org.security.crypt.x509.types;

/**
 * Definitions of the meanings of the bits in the {@link ReasonFlags} BIT STRING
 * defined in section 4.2.1.14 of RFC 2459.
 *
 * @author shivam
 * 
 */
public enum Reasons {

	/** Unused. */
	Unused(7),

	/** KeyCompromise. */
	KeyCompromise(6),

	/** CACompromise. */
	CACompromise(5),

	/** AffiliationChanged. */
	AffiliationChanged(4),

	/** Superseded. */
	Superseded(3),

	/** CessationOfOperation. */
	CessationOfOperation(2),

	/** CertificateHold. */
	CertificateHold(1);

	/** Bit mask value. */
	private final int mask;

	/**
	 * Creates a bit flag with the given bit mask offset.
	 *
	 * @param offset
	 *            Bit mask offset.
	 */
	Reasons(final int offset) {
		mask = 1 << offset;
	}

	/** @return Bit mask value. */
	public int getMask() {
		return mask;
	}
}