package org.security.crypt.io;

import java.io.IOException;
import java.io.InputStream;
import org.bouncycastle.util.encoders.HexEncoder;

/**
 * Decodes hexadecimal character bytes in the wrapped input stream into raw
 * bytes.
 *
 * @author shivam
 * 
 */
public class HexFilterInputStream extends AbstractEncodingFilterInputStream {

	/** Does decoding work. */
	private final HexEncoder encoder = new HexEncoder();

	/**
	 * Creates a hex filter input stream around the given input stream.
	 *
	 * @param in
	 *            Input stream to wrap.
	 */
	public HexFilterInputStream(final InputStream in) {
		super(in);
	}

	/** {@inheritDoc} */
	protected int getDecodeBufferCapacity() {
		return CHUNK_SIZE / 2;
	}

	/** {@inheritDoc} */
	protected void fillBuffer() throws IOException {
		position = 0;
		decodeBuffer.reset();

		final int count = in.read(byteBuffer);
		if (count > 0) {
			encoder.decode(byteBuffer, 0, count, decodeBuffer);
		}
	}
}