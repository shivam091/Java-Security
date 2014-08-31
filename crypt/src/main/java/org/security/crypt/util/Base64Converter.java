package org.security.crypt.util;

import org.bouncycastle.util.encoders.Base64Encoder;
import org.bouncycastle.util.encoders.Encoder;

/**
 * Converts bytes to base-64 encoded strings and vice versa.
 *
 * @author shivam
 * 
 */
public class Base64Converter extends AbstractEncodingConverter {

	/** Does encoding work. */
	private final Base64Encoder encoder = new Base64Encoder();

	/** {@inheritDoc} */
	protected Encoder getEncoder() {
		return encoder;
	}
}