package org.security.crypt.symmetric;

/**
 * Provider of symmetric encryption/decryption operations using Serpent cipher.
 *
 * @author shivam
 * 
 */

public class Serpent extends SymmetricAlgorithm {

	/** Algorithm name. */
	public static final String ALGORITHM = "Serpent";

	/** Available key lengths in bits. */
	public static final int[] KEY_LENGTHS = new int[] { 256, 192, 128, };

	/**
	 * Creates a default Serpent symmetric encryption algorithm using CBC mode
	 * and PKCS5 padding.
	 */
	public Serpent() {
		this(DEFAULT_MODE, DEFAULT_PADDING);
	}

	/**
	 * Creates a default Serpent symmetric encryption algorithm using the given
	 * mode and padding style.
	 *
	 * @param mode
	 *            Cipher mode name.
	 * @param padding
	 *            Cipher padding style name.
	 */
	public Serpent(final String mode, final String padding) {
		super(ALGORITHM, mode, padding);
	}

	/** {@inheritDoc} */
	public int[] getAllowedKeyLengths() {
		return KEY_LENGTHS;
	}
}