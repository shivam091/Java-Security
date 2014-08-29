package org.security.crypt;

/**
 * Describes algorithms that support initialization with an arbitrary amount of
 * random data.
 *
 * @author shivam
 * 
 */
public interface Randomizable {

	/**
	 * Gets the number of random bytes used for calculations that need random
	 * data.
	 *
	 * @return Number of bytes of random data.
	 */
	int getRandomByteSize();

	/**
	 * Sets the number of random bytes used for calculations that need random
	 * data.
	 *
	 * @param size
	 *            Number of bytes to obtain from random provider.
	 */
	void setRandomByteSize(int size);
}