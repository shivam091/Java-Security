package org.security.crypt.x509.types;

import java.util.List;

/**
 * Stores a list of {@link PolicyInformation} objects that could represent the
 * data in the <code>CertificatePolicies</code> extension field defined in
 * section 4.2.1.5 of RFC 2459.
 *
 * @author shivam
 * 
 */
public class PolicyInformationList extends AbstractList<PolicyInformation> {

	/**
	 * Constructs a new instance from the given list of policies.
	 *
	 * @param listOfPolicies
	 *            List of certificate policies.
	 */
	public PolicyInformationList(final List<PolicyInformation> listOfPolicies) {
		if (listOfPolicies == null) {
			throw new IllegalArgumentException(
					"List of policies cannot be null.");
		}
		items = listOfPolicies.toArray(new PolicyInformation[listOfPolicies
				.size()]);
	}

	/**
	 * Constructs a new instance from the given array of policies.
	 *
	 * @param arrayOfPolicies
	 *            Array of policies.
	 */
	public PolicyInformationList(final PolicyInformation[] arrayOfPolicies) {
		if (arrayOfPolicies == null) {
			throw new IllegalArgumentException(
					"Array of policies cannot be null.");
		}
		items = arrayOfPolicies;
	}
}