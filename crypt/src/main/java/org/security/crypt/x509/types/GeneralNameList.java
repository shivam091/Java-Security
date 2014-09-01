package org.security.crypt.x509.types;

import java.util.List;

/**
 * Representation of the <code>GeneralNames</code> type defined in section
 * 4.2.1.7 of RFC 2459, which simply stores a list of {@link GeneralName} items.
 *
 * @author shivam
 * 
 */
public class GeneralNameList extends AbstractList<GeneralName> {

	/**
	 * Constructs a new instance from the given list of names.
	 *
	 * @param listOfNames
	 *            List of names.
	 */
	public GeneralNameList(final List<GeneralName> listOfNames) {
		if (listOfNames == null) {
			throw new IllegalArgumentException("List of names cannot be null.");
		}
		items = listOfNames.toArray(new GeneralName[listOfNames.size()]);
	}

	/**
	 * Constructs a new instance from the given array of names.
	 *
	 * @param arrayOfNames
	 *            Array of names.
	 */
	public GeneralNameList(final GeneralName[] arrayOfNames) {
		if (arrayOfNames == null) {
			throw new IllegalArgumentException("Array of names cannot be null.");
		}
		items = arrayOfNames;
	}
}