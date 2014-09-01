package org.security.crypt.tasks;

import org.security.crypt.symmetric.SymmetricAlgorithm;
import org.security.crypt.util.Base64Converter;
import org.apache.tools.ant.BuildException;

/**
 * <p>
 * <code>DecryptPropertyTask</code> will decrypt an ant property using a
 * symmetric algorithm. Encrypted value must be BASE64 encoded.
 * </p>
 *
 * @author shivam
 * 
 */
public final class DecryptPropertyTask extends AbstractCryptTask {

	/**
	 * <p>
	 * See @link{org.apache.tools.ant.Task}.
	 * </p>
	 */
	public void execute() {
		try {
			final SymmetricAlgorithm crypt = createAlgorithm();
			crypt.initDecrypt();

			final String propertyValue = this.getProject().getProperty(
					this.propertyName);
			final String decryptValue = new String(crypt.decrypt(propertyValue,
					new Base64Converter()));
			this.getProject().setProperty(this.propertyName, decryptValue);
		} catch (Exception e) {
			e.printStackTrace();
			throw new BuildException(e);
		}
	}
}