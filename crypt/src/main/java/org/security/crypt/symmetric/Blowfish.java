package org.security.crypt.symmetric;

/**
 * Provider of symmetric encryption/decryption operations using Blowfish cipher.
 *
 * @author shivam
 * 
 */

public class Blowfish extends SymmetricAlgorithm {

	/** Algorithm name. */
	public static final String ALGORITHM = "Blowfish";

	/** Minimum key length in bits. */
	public static final int MIN_KEY_LENGTH = 32;

	/** Maximum key length in bits. */
	public static final int MAX_KEY_LENGTH = 448;

	/** Available key lengths in bits. */
	public static final int[] KEY_LENGTHS = new int[] { 448, 384, 320, 256,
			192, 128, 64, };

	/** Number of bits in byte. */
	private static final int BITS_IN_BYTE = 8;

	/**
	 * Creates a default CAST5 symmetric encryption algorithm using CBC mode and
	 * PKCS5 padding.
	 */
	public Blowfish() {
		this(DEFAULT_MODE, DEFAULT_PADDING);
	}

	/**
	 * Creates a default Blowfish symmetric encryption algorithm using the given
	 * mode and padding style.
	 *
	 * @param mode
	 *            Cipher mode name.
	 * @param padding
	 *            Cipher padding style name.
	 */
	public Blowfish(final String mode, final String padding) {
		super(ALGORITHM, mode, padding);
	}

	/** {@inheritDoc} */
	public int[] getAllowedKeyLengths() {
		return KEY_LENGTHS;
	}

	/** {@inheritDoc} */
	public int getMinKeyLength() {
		return MIN_KEY_LENGTH;
	}

	/** {@inheritDoc} */
	public int getMaxKeyLength() {
		return MAX_KEY_LENGTH;
	}

	/** {@inheritDoc} */
	public boolean isValidKeyLength(final int bitLength) {
		if (bitLength < MIN_KEY_LENGTH || bitLength > MAX_KEY_LENGTH) {
			return false;
		} else {
			return bitLength % BITS_IN_BYTE == 0;
		}
	}
}