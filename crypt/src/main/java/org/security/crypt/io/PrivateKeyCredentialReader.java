package org.security.crypt.io;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.PrivateKey;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;

import org.security.crypt.CryptException;
import org.security.crypt.CryptProvider;
import org.security.crypt.pbe.EncryptionScheme;
import org.security.crypt.pbe.OpenSSLEncryptionScheme;
import org.security.crypt.pbe.PBES1EncryptionScheme;
import org.security.crypt.pbe.PBES2EncryptionScheme;
import org.security.crypt.pkcs.PBEParameter;
import org.security.crypt.pkcs.PBES1Algorithm;
import org.security.crypt.pkcs.PBES2CipherGenerator;
import org.security.crypt.pkcs.PBKDF2Parameters;
import org.security.crypt.util.Convert;
import org.security.crypt.util.ECUtils;
import org.security.crypt.util.PemHelper;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * Reads encoded private keys in PKCS#8 or OpenSSL "traditional" format. Both
 * PEM and DER encodings are supported.
 *
 * @author shivam
 * 
 */
public class PrivateKeyCredentialReader extends
		AbstractEncodedCredentialReader<PrivateKey> {

	/**
	 * Reads an encrypted private key in PKCS#8 or OpenSSL "traditional" format
	 * from a file into a {@link PrivateKey} object. Both DER and PEM encoded
	 * keys are supported.
	 *
	 * @param file
	 *            Private key file.
	 * @param password
	 *            Password to decrypt private key.
	 *
	 * @return Private key containing data read from file.
	 *
	 * @throws CryptException
	 *             On key format errors.
	 * @throws IOException
	 *             On key read errors.
	 */
	@SuppressWarnings("resource")
	public PrivateKey read(final File file, final char[] password)
			throws IOException, CryptException {
		byte[] data = IOHelper.read(new FileInputStream(file).getChannel());
		data = decryptKey(data, password);
		return decode(data);
	}

	/**
	 * Reads an encrypted private key in PKCS#8 or OpenSSL "traditional" format
	 * from a file into a {@link PrivateKey} object. Both DER and PEM encoded
	 * keys are supported.
	 *
	 * @param in
	 *            Input stream containing private key data.
	 * @param password
	 *            Password to decrypt private key; MUST NOT be null.
	 *
	 * @return Private key containing data read from file.
	 *
	 * @throws IOException
	 *             On IO errors.
	 * @throws CryptException
	 *             On cryptography errors such as invalid formats, unsupported
	 *             ciphers, illegal settings.
	 */
	public PrivateKey read(final InputStream in, final char[] password)
			throws CryptException, IOException {
		byte[] data = IOHelper.read(in);
		data = decryptKey(data, password);
		return decode(data);
	}

	/** {@inheritDoc} */
	protected PrivateKey decode(final byte[] encoded) throws CryptException {
		final KeySpec spec;
		final String algorithm;

		final ASN1Object o;
		try {
			o = ASN1Object.fromByteArray(encoded);
		} catch (Exception e) {
			throw new CryptException("Key is not ASN.1 encoded data.");
		}

		// Assume PKCS#8 and try OpenSSL "traditional" format as backup
		PrivateKeyInfo pi;
		try {
			pi = PrivateKeyInfo.getInstance(o);
		} catch (Exception e) {
			pi = null;
		}
		if (pi != null) {
			final String algOid = pi.getAlgorithmId().getObjectId().getId();
			if (RSA_ID.equals(pi.getAlgorithmId().getObjectId())) {
				algorithm = "RSA";
			} else if (EC_ID.equals(pi.getAlgorithmId().getObjectId())) {
				algorithm = "EC";
			} else if (DSA_ID.equals(pi.getAlgorithmId().getObjectId())) {
				algorithm = "DSA";
			} else {
				throw new CryptException("Unsupported PKCS#8 algorithm ID "
						+ algOid);
			}
			try {
				spec = new PKCS8EncodedKeySpec(encoded);
			} catch (Exception e) {
				throw new CryptException("Invalid PKCS#8 private key format.",
						e);
			}
		} else if (o instanceof DERObjectIdentifier) {
			// Indicates we have an EC key in the default OpenSSL format emitted
			// by
			//
			// openssl ecparam -name xxxx -genkey
			//
			// which is the concatenation of the named curve OID and a sequence
			// of 1
			// containing the private point
			algorithm = "EC";

			final DERObjectIdentifier oid = (DERObjectIdentifier) o;
			final int len = encoded[1];
			final byte[] privatePart = new byte[encoded.length - len - 2];
			System.arraycopy(encoded, len + 2, privatePart, 0,
					privatePart.length);
			try {
				final ASN1Sequence seq = (ASN1Sequence) ASN1Sequence
						.fromByteArray(privatePart);
				spec = new ECPrivateKeySpec(DERInteger.getInstance(
						seq.getObjectAt(0)).getValue(),
						ECUtils.fromNamedCurve(oid));
			} catch (IOException e) {
				throw new CryptException(
						"Error reading elliptic curve key data.", e);
			}
		} else {
			// OpenSSL "traditional" format is an ASN.1 sequence of key
			// parameters

			// Detect key type based on number and types of parameters:
			// RSA -> {version, mod, pubExp, privExp, prime1, prime2, exp1,
			// exp2, c}
			// DSA -> {version, p, q, g, pubExp, privExp}
			// EC -> {version, privateKey, parameters, publicKey}
			final DERSequence sequence = (DERSequence) o;
			if (sequence.size() == 9) {
				if (logger.isDebugEnabled()) {
					logger.debug("Reading OpenSSL format RSA private key.");
				}
				algorithm = "RSA";
				try {
					spec = new RSAPrivateCrtKeySpec(DERInteger.getInstance(
							sequence.getObjectAt(1)).getValue(), DERInteger
							.getInstance(sequence.getObjectAt(2)).getValue(),
							DERInteger.getInstance(sequence.getObjectAt(3))
									.getValue(), DERInteger.getInstance(
									sequence.getObjectAt(4)).getValue(),
							DERInteger.getInstance(sequence.getObjectAt(5))
									.getValue(), DERInteger.getInstance(
									sequence.getObjectAt(6)).getValue(),
							DERInteger.getInstance(sequence.getObjectAt(7))
									.getValue(), DERInteger.getInstance(
									sequence.getObjectAt(8)).getValue());
				} catch (Exception e) {
					throw new CryptException("Invalid RSA key.", e);
				}
			} else if (sequence.size() == 6) {
				if (logger.isDebugEnabled()) {
					logger.debug("Reading OpenSSL format DSA private key.");
				}
				algorithm = "DSA";
				try {
					spec = new DSAPrivateKeySpec(DERInteger.getInstance(
							sequence.getObjectAt(5)).getValue(), DERInteger
							.getInstance(sequence.getObjectAt(1)).getValue(),
							DERInteger.getInstance(sequence.getObjectAt(2))
									.getValue(), DERInteger.getInstance(
									sequence.getObjectAt(3)).getValue());
				} catch (Exception e) {
					throw new CryptException("Invalid DSA key.", e);
				}
			} else if (sequence.size() == 4) {
				if (logger.isDebugEnabled()) {
					logger.debug("Reading OpenSSL format EC private key.");
				}
				algorithm = "EC";
				spec = ECUtils.readEncodedPrivateKey(sequence);
			} else {
				throw new CryptException(
						"Invalid OpenSSL traditional private key format.");
			}
		}
		try {
			return CryptProvider.getKeyFactory(algorithm).generatePrivate(spec);
		} catch (InvalidKeySpecException e) {
			throw new CryptException("Invalid key specification", e);
		}
	}

	/**
	 * Decrypts an encrypted key in either PKCS#8 or OpenSSL "traditional"
	 * format. Both PEM and DER encodings are supported.
	 *
	 * @param encrypted
	 *            Encoded encrypted key data.
	 * @param password
	 *            Password to decrypt key.
	 *
	 * @return Decrypted key.
	 *
	 * @throws IOException
	 *             On IO errors.
	 * @throws CryptException
	 *             On key decryption errors.
	 */
	private byte[] decryptKey(final byte[] encrypted, final char[] password)
			throws IOException, CryptException {
		if (password == null || password.length == 0) {
			throw new IllegalArgumentException(
					"Password is required for decrypting an encrypted private key.");
		}

		byte[] bytes = encrypted;
		if (PemHelper.isPem(encrypted)) {
			if (logger.isDebugEnabled()) {
				logger.debug("Reading PEM encoded private key.");
			}

			final String pem = new String(encrypted, "ASCII");
			if (pem.contains(PemHelper.PROC_TYPE)) {
				bytes = decryptOpenSSLKey(pem, password);
			} else {
				bytes = decryptPKCS8Key(PemHelper.decode(bytes), password);
			}
		} else {
			bytes = decryptPKCS8Key(bytes, password);
		}
		return bytes;
	}

	/**
	 * Decrypts a DER-encoded private key in PKCS#8 format.
	 *
	 * @param encrypted
	 *            Bytes of DER-encoded encrypted private key.
	 * @param password
	 *            Password to decrypt private key.
	 *
	 * @return ASN.1 encoded bytes of decrypted key.
	 *
	 * @throws CryptException
	 *             On key decryption errors.
	 */
	private byte[] decryptOpenSSLKey(final String encrypted,
			final char[] password) throws CryptException {
		try {
			final int start = encrypted.indexOf(PemHelper.DEK_INFO);
			final int eol = encrypted.indexOf('\n', start);
			final String[] dekInfo = encrypted.substring(start + 10, eol)
					.split(",");
			final String alg = dekInfo[0];
			final byte[] iv = Convert.fromHex(dekInfo[1]);
			final byte[] bytes = PemHelper.decode(encrypted);
			return new OpenSSLEncryptionScheme(alg, iv)
					.decrypt(password, bytes);
		} catch (Exception e) {
			throw new CryptException("Failed decrypting OpenSSL key.", e);
		}
	}

	/**
	 * Decrypts a DER-encoded private key in PKCS#8 format.
	 *
	 * @param encrypted
	 *            Bytes of DER-encoded encrypted private key.
	 * @param password
	 *            Password to decrypt private key.
	 *
	 * @return ASN.1 encoded bytes of decrypted key.
	 *
	 * @throws CryptException
	 *             On key decryption errors.
	 */
	private byte[] decryptPKCS8Key(final byte[] encrypted, final char[] password)
			throws CryptException {
		final EncryptionScheme scheme;
		try {
			final EncryptedPrivateKeyInfo ki = EncryptedPrivateKeyInfo
					.getInstance(ASN1Object.fromByteArray(encrypted));
			final AlgorithmIdentifier alg = ki.getEncryptionAlgorithm();
			if (PKCSObjectIdentifiers.id_PBES2.equals(alg.getObjectId())) {
				// PBES2 has following parameters:
				// {
				// {id-PBKDF2, {salt, iterationCount, keyLength (optional)}}
				// {encryptionAlgorithmOid, iv}
				// }
				final DERSequence pbeSeq = (DERSequence) alg.getParameters();
				final PBKDF2Parameters kdfParms = PBKDF2Parameters
						.decode((DERSequence) pbeSeq.getObjectAt(0));
				final PBES2CipherGenerator cipherGen = new PBES2CipherGenerator(
						(DERSequence) pbeSeq.getObjectAt(1));
				if (kdfParms.getLength() == 0) {
					kdfParms.setLength(cipherGen.getKeySize() / 8);
				}
				scheme = new PBES2EncryptionScheme(cipherGen.generate(),
						kdfParms);
			} else {
				// Use PBES1 encryption scheme to decrypt key
				scheme = new PBES1EncryptionScheme(PBES1Algorithm.fromOid(alg
						.getObjectId().getId()),
						PBEParameter.decode((DERSequence) alg.getParameters()));
			}
			return scheme.decrypt(password, ki.getEncryptedData());
		} catch (Exception e) {
			throw new CryptException("Failed decrypting PKCS#8 private key", e);
		}
	}
}