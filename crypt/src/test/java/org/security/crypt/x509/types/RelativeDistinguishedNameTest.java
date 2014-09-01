package org.security.crypt.x509.types;

import org.testng.AssertJUnit;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

/**
 * Unit test for {@link RelativeDistinguishedName} class.
 *
 * @author shivam
 * 
 */
public class RelativeDistinguishedNameTest {

	/**
	 * @return RDN test data.
	 *
	 * @throws Exception
	 *             On test data generation failure.
	 */
	@DataProvider(name = "rdndata")
	public Object[][] createRDNTestData() throws Exception {
		return new Object[][] {
				{
						new RelativeDistinguishedName(
								new AttributeTypeAndValue(
										AttributeType.DomainComponent, "vt")),
						"DC=vt", },
				{
						new RelativeDistinguishedName(
								new AttributeTypeAndValue[] {
										new AttributeTypeAndValue(
												AttributeType.OrganizationalUnitName,
												"Sales"),
										new AttributeTypeAndValue(
												AttributeType.CommonName,
												"J. Smith"), }),
						"OU=Sales+CN=J. Smith", }, };
	}

	/**
	 * @param rdn
	 *            Test value to perform toString() on.
	 * @param expected
	 *            Expected string value.
	 */
	@Test(groups = { "functest", "x509" }, dataProvider = "rdndata")
	public void testToString(final RelativeDistinguishedName rdn,
			final String expected) {
		AssertJUnit.assertEquals(rdn.toString(), expected);
	}
}