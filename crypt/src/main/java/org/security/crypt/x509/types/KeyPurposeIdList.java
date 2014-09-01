package org.security.crypt.x509.types;

import java.util.List;

/**
 * Represents the sequence of <code>KeyPurposeId</code> types that are contained
 * in the <code>ExtendedKeyUsage</code> extension field described in section
 * 4.2.1.13 of RFC 2459.
 *
 * @author shivam
 * 
 */
public class KeyPurposeIdList extends AbstractList<KeyPurposeId> {

	/**
	 * Constructs a new instance from the given list of key purpose identifiers.
	 *
	 * @param listOfKeyPurposeIds
	 *            List of key purpose identifiers.
	 */
	public KeyPurposeIdList(final List<KeyPurposeId> listOfKeyPurposeIds) {
		if (listOfKeyPurposeIds == null) {
			throw new IllegalArgumentException(
					"List of key purpose IDs cannot be null.");
		}
		items = listOfKeyPurposeIds
				.toArray(new KeyPurposeId[listOfKeyPurposeIds.size()]);
	}

	/**
	 * Constructs a new instance from the given array of key purpose
	 * identifiers.
	 *
	 * @param arrayOfKeyPurposeIds
	 *            Array of key purpose identifiers.
	 */
	public KeyPurposeIdList(final KeyPurposeId[] arrayOfKeyPurposeIds) {
		if (arrayOfKeyPurposeIds == null) {
			throw new IllegalArgumentException(
					"Array of key purpose IDs  cannot be null.");
		}
		items = arrayOfKeyPurposeIds;
	}
}