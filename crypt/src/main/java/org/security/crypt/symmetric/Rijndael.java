package org.security.crypt.symmetric;

/**
 * Provider of symmetric encryption/decryption operations using Rijndael cipher.
 *
 * @author shivam
 * 
 */

public class Rijndael extends SymmetricAlgorithm {

	/** Algorithm name. */
	public static final String ALGORITHM = "Rijndael";

	/** Available key lengths in bits. */
	public static final int[] KEY_LENGTHS = new int[] { 256, 224, 192, 160,
			128, };

	/**
	 * Creates a default Rijndael symmetric encryption algorithm using CBC mode
	 * and PKCS5 padding.
	 */
	public Rijndael() {
		this(DEFAULT_MODE, DEFAULT_PADDING);
	}

	/**
	 * Creates a default Rijndael symmetric encryption algorithm using the given
	 * mode and padding style.
	 *
	 * @param mode
	 *            Cipher mode name.
	 * @param padding
	 *            Cipher padding style name.
	 */
	public Rijndael(final String mode, final String padding) {
		super(ALGORITHM, mode, padding);
	}

	/** {@inheritDoc} */
	public int[] getAllowedKeyLengths() {
		return KEY_LENGTHS;
	}
}