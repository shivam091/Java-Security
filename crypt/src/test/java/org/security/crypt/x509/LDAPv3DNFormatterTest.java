package org.security.crypt.x509;

import java.io.File;
import java.security.cert.X509Certificate;

import org.security.crypt.util.CryptReader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testng.AssertJUnit;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

/**
 * Unit test for {@link LDAPv3DNFormatter} class.
 *
 * @author shivam
 * 
 */
public class LDAPv3DNFormatterTest {

	/** Path to directory containing test resources. */
	private static final String RESOURCE_DIR = "src/test/resources/x509";

	/** Logger instance. */
	private final Logger logger = LoggerFactory.getLogger(this.getClass());

	/**
	 * @return Certificate test data.
	 *
	 * @throws Exception
	 *             On test data generation failure.
	 */
	@DataProvider(name = "certdata")
	public Object[][] createCertificateTestData() throws Exception {
		return new Object[][] {
				{
						new File(RESOURCE_DIR, "serac-dev-test-cert.pem"),
						"C=US,DC=vt,DC=edu,O=Virginia Polytechnic Institute and "
								+ "State University,CN=Marvin S Addison,UID=1145718",
						"SERIALNUMBER=12,CN=DEV Virginia Tech Class 1 Server CA,"
								+ "O=Virginia Polytechnic Institute and State University,"
								+ "C=US,DC=vt,DC=edu", },
				{
						new File(RESOURCE_DIR, "glider.cc.vt.edu.crt"),
						"C=US,DC=edu,DC=vt,ST=Virginia,L=Blacksburg,"
								+ "O=Virginia Polytechnic Institute and State University,"
								+ "OU=Middleware-Client,OU=SETI,SERIALNUMBER=1248110657961,"
								+ "CN=glider.cc.vt.edu",
						"CN=Virginia Tech Middleware CA,"
								+ "O=Virginia Polytechnic Institute and State University,"
								+ "C=US,DC=vt,DC=edu", }, };
	}

	/**
	 * @param certFile
	 *            File containing X.509 certificate data.
	 * @param expectedSubjectDn
	 *            Expected certficate subject DN.
	 * @param expectedIssuerDn
	 *            Expected certficate issuer DN.
	 *
	 * @throws Exception
	 *             On test failure.
	 */
	@Test(groups = { "functest", "x509" }, dataProvider = "certdata")
	public void testFormat(final File certFile, final String expectedSubjectDn,
			final String expectedIssuerDn) throws Exception {
		logger.info("Testing formatting subject and issuer DNs of {}", certFile);

		final X509Certificate cert = (X509Certificate) CryptReader
				.readCertificate(certFile);
		final LDAPv3DNFormatter formatter = new LDAPv3DNFormatter();
		AssertJUnit.assertEquals(expectedSubjectDn,
				formatter.format(cert.getSubjectX500Principal()));
		AssertJUnit.assertEquals(expectedIssuerDn,
				formatter.format(cert.getIssuerX500Principal()));
	}
}