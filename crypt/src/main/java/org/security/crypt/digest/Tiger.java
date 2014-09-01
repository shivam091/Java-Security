package org.security.crypt.digest;

import java.security.SecureRandom;
import org.bouncycastle.crypto.digests.TigerDigest;

/**
 * <p>
 * <code>Tiger</code> contains functions for hashing data using the Tiger
 * algorithm. This algorithm outputs a 192 bit hash.
 * </p>
 *
 * @author shivam
 * 
 */

public class Tiger extends DigestAlgorithm {

	/** Creates an uninitialized instance of an Tiger digest. */
	public Tiger() {
		super(new TigerDigest());
	}

	/**
	 * Creates a new Tiger digest that may optionally be initialized with random
	 * data.
	 *
	 * @param randomize
	 *            True to randomize initial state of digest, false otherwise.
	 */
	public Tiger(final boolean randomize) {
		super(new TigerDigest());
		if (randomize) {
			setRandomProvider(new SecureRandom());
			setSalt(getRandomSalt());
		}
	}

	/**
	 * Creates a new Tiger digest and initializes it with the given salt.
	 *
	 * @param salt
	 *            Salt data used to initialize digest computation.
	 */
	public Tiger(final byte[] salt) {
		super(new TigerDigest());
		setSalt(salt);
	}
}