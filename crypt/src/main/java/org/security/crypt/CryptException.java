package org.security.crypt;

/**
 * <p>
 * <code>CryptException</code> encapsulates the many exceptions that can occur
 * when working with the crypt libs.
 * </p>
 *
 * @author shivam
 * 
 */

public final class CryptException extends Exception {

	/** CryptException.java. */
	private static final long serialVersionUID = -1041478966786912109L;

	/**
	 * <p>
	 * This creates a new <code>CryptException</code>.
	 * </p>
	 */
	public CryptException() {
	}

	/**
	 * <p>
	 * This creates a new <code>CryptException</code> with the supplied message.
	 * </p>
	 *
	 * @param msg
	 *            <code>String</code>
	 */
	public CryptException(final String msg) {
		super(msg);
	}

	/**
	 * <p>
	 * This creates a new <code>CryptException</code> with the supplied cause.
	 * </p>
	 *
	 * @param cause
	 *            <code>Exception</code>
	 */
	public CryptException(final Throwable cause) {
		super(cause);
	}

	/**
	 * <p>
	 * This creates a new <code>CryptException</code> with the supplied message
	 * and cause.
	 * </p>
	 *
	 * @param msg
	 *            <code>String</code>
	 * @param cause
	 *            <code>Throwable</code>
	 */
	public CryptException(final String msg, final Throwable cause) {
		super(msg, cause);
	}
}