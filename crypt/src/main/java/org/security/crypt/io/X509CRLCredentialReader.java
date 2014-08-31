package org.security.crypt.io;

import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CRLException;
import java.security.cert.X509CRL;
import org.security.crypt.CryptException;

/**
 * Credential reader for handling X.509 CRLs. Both PEM and DER encoding of CRL
 * data is supported.
 *
 * @author shivam $Date: 2013-06-25 16:20:29 -0400 (Tue, 25 Jun 2013) $
 */
public class X509CRLCredentialReader extends
		AbstractX509CredentialReader<X509CRL> {

	/** {@inheritDoc} */
	public X509CRL read(final InputStream in) throws IOException,
			CryptException {
		try {
			return (X509CRL) getX509CertificateFactory().generateCRL(in);
		} catch (CRLException e) {
			throw new CryptException("Failed reading X.509 CRL.", e);
		}
	}
}