package org.security.crypt.pbe;

import org.security.crypt.digest.DigestAlgorithm;
import org.bouncycastle.crypto.PBEParametersGenerator;
import org.bouncycastle.crypto.generators.PKCS12ParametersGenerator;

/**
 * Implements the password-based key generation function defined in section B of
 * PKCS#12.
 *
 * @author shivam
 * 
 */
public class PKCS12KeyGenerator extends AbstractPKCSKeyGenerator {

	/** Digest algorithm. */
	private DigestAlgorithm digest;

	/**
	 * Creates a new instance that uses the given digest for the pseudorandom
	 * function.
	 *
	 * @param prf
	 *            Pseudorandom function digest.
	 * @param saltBytes
	 *            Key derivation function salt bytes.
	 * @param iterations
	 *            Key derivation function iteration count.
	 */
	public PKCS12KeyGenerator(final DigestAlgorithm prf,
			final byte[] saltBytes, final int iterations) {
		if (prf == null) {
			throw new IllegalArgumentException("Digest cannot be null.");
		}
		this.digest = prf;
		this.salt = saltBytes;
		setIterationCount(iterations);
	}

	/** {@inheritDoc} */
	protected PBEParametersGenerator newParamGenerator() {
		return new PKCS12ParametersGenerator(digest.getDigest());
	}

	/** {@inheritDoc} */
	protected byte[] toBytes(final char[] password) {
		return PBEParametersGenerator.PKCS12PasswordToBytes(password);
	}
}