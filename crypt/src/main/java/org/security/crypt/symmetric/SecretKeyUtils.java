package org.security.crypt.symmetric;

import java.security.SecureRandom;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import org.security.crypt.CryptException;
import org.security.crypt.CryptProvider;

/**
 * Utility class with methods for handling secret keys.
 *
 * @author shivam
 * 
 */
public final class SecretKeyUtils {

	/** Default random data provider for key generation. */
	private static final SecureRandom DEFAULT_RANDOM = new SecureRandom();

	/**
	 * Gets the key size in bits, which is simply the size of the encoded data
	 * in bytes converted to bits.
	 *
	 * @param key
	 *            Secret key.
	 *
	 * @return Key size in bits.
	 */
	public int length(final SecretKey key) {
		return key.getEncoded().length * 8;
	}

	/**
	 * Generates a new secret key of the prescribed length that is suitable for
	 * the given algorithm.
	 *
	 * @param algorithm
	 *            Name of cipher algorithm for which a suitable key will be
	 *            generated.
	 * @param bitLength
	 *            Bit length required in generated key. Valid key lengths are
	 *            commonly a function of the cipher algorithm.
	 *
	 * @return New secret key for use with cipher of given algorithm name.
	 *
	 * @throws CryptException
	 *             if the private key cannot be generated
	 */
	public static SecretKey generate(final String algorithm, final int bitLength)
			throws CryptException {
		return generate(algorithm, bitLength, DEFAULT_RANDOM);
	}

	/**
	 * Generates a new secret key of the prescribed length that is suitable for
	 * the given algorithm.
	 *
	 * @param algorithm
	 *            Name of cipher algorithm for which a suitable key will be
	 *            generated.
	 * @param bitLength
	 *            Bit length required in generated key. Valid key lengths are
	 *            commonly a function of the cipher algorithm.
	 * @param random
	 *            Source of random data for key generation operation.
	 *
	 * @return New secret key for use with cipher of given algorithm name.
	 *
	 * @throws CryptException
	 *             if the private key cannot be generated
	 */
	public static SecretKey generate(final String algorithm,
			final int bitLength, final SecureRandom random)
			throws CryptException {
		if (random == null) {
			throw new CryptException("Source of random data cannot be null.");
		}

		final KeyGenerator keyGen = CryptProvider.getKeyGenerator(algorithm);
		keyGen.init(bitLength, random);
		try {
			return keyGen.generateKey();
		} catch (Exception ex) {
			throw new CryptException(String.format(
					"Error generatig %s-bit %s key", bitLength, algorithm), ex);
		}
	}
}