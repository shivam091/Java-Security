package org.security.crypt.x509.types;

import org.testng.AssertJUnit;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

/**
 * Unit test for {@link AttributeTypeAndValue} class.
 *
 * @author shivam
 * 
 */
public class AttributeTypeAndValueTest {

	/**
	 * @return Certificate test data.
	 *
	 * @throws Exception
	 *             On test data generation failure.
	 */
	@DataProvider(name = "atvdata")
	public Object[][] createAttributeTypeAndValueTestData() throws Exception {
		return new Object[][] {
				{
						new AttributeTypeAndValue(AttributeType.CommonName,
								"Marvin S. Addison"), "CN=Marvin S. Addison", },
				{
						new AttributeTypeAndValue(
								AttributeType.OrganizationName,
								"Sue, Grabbit and Runn"),
						"O=Sue\\, Grabbit and Runn", },
				{
						new AttributeTypeAndValue("3.1.4.1.5",
								" Apple, Cherry, and Mixed Berry! "),
						"3.1.4.1.5=\\ Apple\\, Cherry\\, and Mixed Berry!\\ ", }, };
	}

	/**
	 * @param atv
	 *            Test value to perform toString() on.
	 * @param expected
	 *            Expected string value.
	 */
	@Test(groups = { "functest", "x509" }, dataProvider = "atvdata")
	public void testToString(final AttributeTypeAndValue atv,
			final String expected) {
		AssertJUnit.assertEquals(atv.toString(), expected);
	}
}