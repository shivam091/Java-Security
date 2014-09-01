package org.security.crypt.asymmetric;

/**
 * <p>
 * <code>RSA</code> contains functions for encrypting and decrypting using the
 * RSA algorithm. The encryption mode is set to 'NONE'. The padding is set to
 * 'OAEP'. This classes defaults to a key creation length of 2048 bits.
 * </p>
 *
 * @author shivam
 * 
 */

public class RSA extends AsymmetricAlgorithm {

	/** Algorithm name. */
	public static final String ALGORITHM = "RSA";

	/**
	 * Creates a default RSA asymmetric encryption algorithm that uses OAEP
	 * padding.
	 */
	public RSA() {
		super(ALGORITHM);
	}
}