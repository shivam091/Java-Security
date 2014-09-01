package org.security.crypt.symmetric;

/**
 * Provider of symmetric encryption/decryption operations using RC5 cipher.
 *
 * @author shivam
 * 
 */

public class RC5 extends SymmetricAlgorithm {

	/** Algorithm name. */
	public static final String ALGORITHM = "RC5";

	/** Available key lengths in bits. */
	private static final int[] KEY_LENGTHS = new int[] { 2040, 1792, 1536,
			1280, 1024, 768, 512, 256, 128, 64, 32, };

	/**
	 * Creates a default RC5 symmetric encryption algorithm using CBC mode and
	 * PKCS5 padding.
	 */
	public RC5() {
		this(DEFAULT_MODE, DEFAULT_PADDING);
	}

	/**
	 * Creates a default RC5 symmetric encryption algorithm using the given mode
	 * and padding style.
	 *
	 * @param mode
	 *            Cipher mode name.
	 * @param padding
	 *            Cipher padding style name.
	 */
	public RC5(final String mode, final String padding) {
		super(ALGORITHM, mode, padding);
	}

	/** {@inheritDoc} */
	public int[] getAllowedKeyLengths() {
		return KEY_LENGTHS;
	}

	/** {@inheritDoc} */
	public boolean isValidKeyLength(final int bitLength) {
		return bitLength >= getMinKeyLength() && bitLength <= getMaxKeyLength();
	}
}