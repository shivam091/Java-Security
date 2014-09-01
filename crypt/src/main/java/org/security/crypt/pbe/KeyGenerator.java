package org.security.crypt.pbe;

/**
 * Generates secret keys from passwords for password-based encryption schemes.
 *
 * @author shivam
 * 
 */
public interface KeyGenerator {

	/**
	 * Generates a symmetric key from a password for use in password-based
	 * encryption schemes.
	 *
	 * @param password
	 *            Password used as basis for generated key.
	 * @param size
	 *            Size of generated key in bits, unless otherwise noted.
	 *
	 * @return Secret key bytes.
	 */
	byte[] generate(char[] password, int size);
}