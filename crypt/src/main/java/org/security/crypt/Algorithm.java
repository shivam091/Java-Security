package org.security.crypt;

import java.security.SecureRandom;

/**
 * Describes the basic behavior of all crytographic algorithms.
 *
 * @author shivam
 * 
 */
public interface Algorithm {

	/**
	 * Gets the algorithm name.
	 *
	 * @return Algorithm name.
	 */
	String getAlgorithm();

	/**
	 * Sets the source of random data for cryptographic operations needing a
	 * random data source, such as generating a random salt value.
	 *
	 * @param random
	 *            Provider of cryptographically strong random data.
	 */
	void setRandomProvider(final SecureRandom random);

	/**
	 * Gets random bytes from the random provider of this instance in the amount
	 * specified.
	 *
	 * @param nBytes
	 *            Number of bytes of random data to retrieve.
	 *
	 * @return Byte array of random data.
	 */
	byte[] getRandomData(final int nBytes);
}