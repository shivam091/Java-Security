package org.security.crypt.io;

import java.io.ByteArrayOutputStream;

/**
 * Extends {@link java.io.ByteArrayOutputStream} by allowing direct access to
 * the internal byte buffer.
 *
 * @author shivam
 * 
 */
public class DirectByteArrayOutputStream extends ByteArrayOutputStream {

	/** Creates a new instance with a buffer of the default size. */
	public DirectByteArrayOutputStream() {
		super();
	}

	/**
	 * Creates a new instance with a buffer of the given initial capacity.
	 *
	 * @param capacity
	 *            Initial capacity of internal buffer.
	 */
	public DirectByteArrayOutputStream(final int capacity) {
		super(capacity);
	}

	/**
	 * Gets the internal byte buffer.
	 *
	 * @return Internal buffer that holds written bytes.
	 */
	public byte[] getBuffer() {
		return buf;
	}
}