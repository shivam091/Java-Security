package org.security.crypt.x509.types;

/**
 * Interface describing a type that is simply a collection of other types.
 *
 * @param <T>
 *            Type of object contained in collection.
 *
 * @author shivam
 * 
 */
public interface List<T> {

	/** @return Array of items in the collection. */
	T[] getItems();
}