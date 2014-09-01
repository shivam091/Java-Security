package org.security.crypt.pkcs;

import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.RC2ParameterSpec;
import javax.crypto.spec.RC5ParameterSpec;
import org.security.crypt.symmetric.RC2;
import org.security.crypt.symmetric.SymmetricAlgorithm;
import org.security.crypt.util.DERHelper;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;

/**
 * Creates {@link SymmetricAlgorithm} from ASN.1 encoded data describing the
 * encryptionScheme value defined in PKCS#5v2.
 *
 * @author shivam
 * 
 */
public class PBES2CipherGenerator {

	/** PBES2 algorithm. */
	private PBES2Algorithm algorithm;

	/** Size of derived key in bits. */
	private int keySize;

	/** Describes cipher-specific initialization parameters. */
	private AlgorithmParameterSpec algParamSpec;

	/**
	 * Creates a new cipher generator from DER-encoded data describing the
	 * cipher.
	 *
	 * @param seq
	 *            DER-encoded sequence containing algorithm identifier and
	 *            parameters.
	 */
	public PBES2CipherGenerator(final DERSequence seq) {
		// DER sequence is expected to be AlgorithmIdentifier type of PKCS#5
		algorithm = PBES2Algorithm.fromOid(((DERObjectIdentifier) seq
				.getObjectAt(0)).getId());

		final DEREncodable parms = seq.getObjectAt(1);
		DERSequence pSeq;
		switch (algorithm) {

		case RC2:
			pSeq = (DERSequence) parms;

			int effectiveBits = 32;
			int idx;
			if (pSeq.size() > 1) {
				idx = 1;
				effectiveBits = RC2.getEffectiveBits(DERHelper.asInt(pSeq
						.getObjectAt(0)));
				algParamSpec = new RC2ParameterSpec(effectiveBits,
						DERHelper.asOctets(pSeq.getObjectAt(idx)));
			}
			keySize = effectiveBits;
			break;

		case RC5:
			pSeq = (DERSequence) parms;

			final int version = DERHelper.asInt(pSeq.getObjectAt(0));
			final int rounds = DERHelper.asInt(pSeq.getObjectAt(1));
			final int blkSize = DERHelper.asInt(pSeq.getObjectAt(2));
			if (pSeq.size() > 3) {
				algParamSpec = new RC5ParameterSpec(version, rounds, blkSize,
						DERHelper.asOctets(pSeq.getObjectAt(3)));
			} else {
				algParamSpec = new RC5ParameterSpec(version, rounds, blkSize);
			}
			keySize = algorithm.getKeySize();
			break;

		default:
			algParamSpec = new IvParameterSpec(DERHelper.asOctets(parms));
			keySize = algorithm.getKeySize();
		}
	}

	/**
	 * Generates a symmetric cipher algorithm from decoded state data.
	 *
	 * @return Symmetric cipher instance.
	 */
	public SymmetricAlgorithm generate() {
		return SymmetricAlgorithm
				.newInstance(algorithm.getSpec(), algParamSpec);
	}

	/**
	 * Gets the key size defined for this algorithm, if any.
	 *
	 * @return Key size in bits, -1 otherwise.
	 */
	public int getKeySize() {
		return keySize;
	}
}