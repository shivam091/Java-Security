package org.security.crypt.tasks;

import org.security.crypt.symmetric.SymmetricAlgorithm;
import org.security.crypt.util.Base64Converter;
import org.security.crypt.util.Convert;
import org.apache.tools.ant.BuildException;

/**
 * <p>
 * <code>EncryptPropertyTask</code> will encrypt an ant property using a
 * symmetric algorithm. Encrypted value will be BASE64 encoded.
 * </p>
 *
 * @author shivam
 * 
 */
public final class EncryptPropertyTask extends AbstractCryptTask {

	/**
	 * <p>
	 * See @link{org.apache.tools.ant.Task}.
	 * </p>
	 */
	public void execute() {
		try {
			final SymmetricAlgorithm crypt = createAlgorithm();
			crypt.initEncrypt();

			final String propertyValue = this.getProject().getProperty(
					this.propertyName);
			final String encryptValue = crypt.encrypt(
					Convert.toBytes(propertyValue), new Base64Converter());
			this.getProject().setProperty(this.propertyName, encryptValue);
		} catch (Exception e) {
			e.printStackTrace();
			throw new BuildException(e);
		}
	}
}