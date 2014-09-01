package org.security.crypt.symmetric;

/**
 * Provider of symmetric encryption/decryption operations using Skipjack cipher.
 *
 * @author shivam
 * 
 */

public class Skipjack extends SymmetricAlgorithm {

	/** Algorithm name. */
	public static final String ALGORITHM = "Skipjack";

	/** Available key lengths in bits. */
	public static final int[] KEY_LENGTHS = new int[] { 80 };

	/**
	 * Creates a default Skipjack symmetric encryption algorithm using CBC mode
	 * and PKCS5 padding.
	 */
	public Skipjack() {
		this(DEFAULT_MODE, DEFAULT_PADDING);
	}

	/**
	 * Creates a default Skipjack symmetric encryption algorithm using the given
	 * mode and padding style.
	 *
	 * @param mode
	 *            Cipher mode name.
	 * @param padding
	 *            Cipher padding style name.
	 */
	public Skipjack(final String mode, final String padding) {
		super(ALGORITHM, mode, padding);
	}

	/** {@inheritDoc} */
	public int[] getAllowedKeyLengths() {
		return KEY_LENGTHS;
	}
}