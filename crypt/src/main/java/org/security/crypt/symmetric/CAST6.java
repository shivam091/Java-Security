package org.security.crypt.symmetric;

/**
 * Provider of symmetric encryption/decryption operations using CAST6 cipher.
 *
 * @author shivam
 * 
 */

public class CAST6 extends SymmetricAlgorithm {

	/** Algorithm name. */
	public static final String ALGORITHM = "CAST6";

	/** Available key lengths in bits. */
	public static final int[] KEY_LENGTHS = new int[] { 256, 224, 192, 160,
			128, };

	/**
	 * Creates a default CAST6 symmetric encryption algorithm using CBC mode and
	 * PKCS5 padding.
	 */
	public CAST6() {
		this(DEFAULT_MODE, DEFAULT_PADDING);
	}

	/**
	 * Creates a default CAST5 symmetric encryption algorithm using the given
	 * mode and padding style.
	 *
	 * @param mode
	 *            Cipher mode name.
	 * @param padding
	 *            Cipher padding style name.
	 */
	public CAST6(final String mode, final String padding) {
		super(ALGORITHM, mode, padding);
	}

	/** {@inheritDoc} */
	public int[] getAllowedKeyLengths() {
		return KEY_LENGTHS;
	}
}