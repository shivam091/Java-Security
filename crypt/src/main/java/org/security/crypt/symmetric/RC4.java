package org.security.crypt.symmetric;

/**
 * Provider of symmetric encryption/decryption operations using RC4 cipher.
 *
 * @author shivam
 * 
 */

public class RC4 extends SymmetricAlgorithm {

	/** Algorithm name. */
	public static final String ALGORITHM = "RC4";

	/** Available key lengths in bits. */
	public static final int[] KEY_LENGTHS = new int[] { 256, 128, 64, 56, 48,
			40, };

	/** Creates a RC4 symmetric encryption algorithm. */
	public RC4() {
		// RC4 is a stream cipher and does not support a mode or padding
		super(ALGORITHM, null, null);
	}

	/**
	 * Creates a RC4 symmetric encryption algorithm. The mode and padding
	 * arguments are ignored since this is a stream cipher and does not support
	 * a block mode or padding; it is provided for consistency with other
	 * ciphers only.
	 *
	 * @param mode
	 *            Cipher mode name -- ignored.
	 * @param padding
	 *            Cipher padding style name -- ignored.
	 */
	public RC4(final String mode, final String padding) {
		super(ALGORITHM, null, null);
	}

	/**
	 * Sets the encryption initialization vector. A unique IV should be
	 * specified for each encryption operation using the same key for good
	 * security. Use the {@link #getRandomIV()} method to obtain random
	 * initialization data of the appropriate size for the chosen cipher.
	 *
	 * <p>
	 * IV data is used upon calling either {@link #initEncrypt()} or
	 * {@link #initDecrypt()}.
	 * </p>
	 *
	 * @param ivBytes
	 *            Initialization bytes; in many cases the size of data should be
	 *            equal to the cipher block size.
	 */
	public void setIV(final byte[] ivBytes) {
		throw new IllegalArgumentException("RC4 does not permit an IV.");
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