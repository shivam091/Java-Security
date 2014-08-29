package org.security.crypt;

/**
 * Abstract base class for all algorithms that can be initialized with an
 * arbitrary amount of random data.
 *
 * @author shivam
 * 
 */
public abstract class AbstractRandomizableAlgorithm extends AbstractAlgorithm
		implements Randomizable {

	/** Default number of random bytes. */
	private static final int DEFAULT_RANDOM_BYTE_SIZE = 256;

	/** Number of bytes used for random data needs. */
	protected int randomByteSize = DEFAULT_RANDOM_BYTE_SIZE;

	/**
	 * Gets the number of random bytes used for calculations that need random
	 * data.
	 *
	 * @return Number of bytes of random data.
	 */
	public int getRandomByteSize() {
		return this.randomByteSize;
	}

	/**
	 * Sets the number of random bytes used for calculations that need random
	 * data.
	 *
	 * @param size
	 *            Number of bytes to obtain from random provider.
	 */
	public void setRandomByteSize(final int size) {
		this.randomByteSize = size;
	}
}