package org.security.crypt.x509.types;

import java.util.Arrays;
import org.security.crypt.util.HexConverter;

/**
 * Friendly representation of an OCTET STRING representing key identifier data
 * as described in section 4.2.1.1 of RFC 2459.
 *
 * @author shivam
 * 
 */
public class KeyIdentifier {

	/** Hash code scale factor. */
	private static final int HASH_FACTOR = 31;

	/** Converts the key id bytes to a friendly hex fingerprint. */
	private final HexConverter converter = new HexConverter(true);

	/** Key identifier bytes. */
	private final byte[] identifier;

	/**
	 * Creates a new key identifier with the given identifier bytes.
	 *
	 * @param id
	 *            Key identifier bytes.
	 */
	public KeyIdentifier(final byte[] id) {
		identifier = id;
	}

	/**
	 * Creates a new key identifier with the given key identifier fingerprint.
	 *
	 * @param fingerprint
	 *            Key identifier fingerprint, e.g.,
	 *            25:48:2F:28:EC:5D:19:BB:1D:25:AE:94:93:B1:7B:B5:35:96:24:66.
	 */
	public KeyIdentifier(final String fingerprint) {
		identifier = converter.toBytes(fingerprint);
	}

	/** @return Key identifier bytes. */
	public byte[] getIdentifier() {
		return identifier;
	}

	/**
	 * @return Key identifier bytes as a hex fingerprint where each pair of hex
	 *         digits are separated by colons.
	 */
	@Override
	public String toString() {
		return converter.fromBytes(identifier);
	}

	/** {@inheritDoc} */
	@Override
	public boolean equals(final Object obj) {
		boolean result;
		if (obj == this) {
			result = true;
		} else if (obj == null || obj.getClass() != getClass()) {
			result = false;
		} else {
			final KeyIdentifier other = (KeyIdentifier) obj;
			result = Arrays.equals(identifier, other.getIdentifier());
		}
		return result;
	}

	/** {@inheritDoc} */
	@Override
	public int hashCode() {
		return HASH_FACTOR * getClass().hashCode()
				+ Arrays.hashCode(identifier);
	}
}