package org.randomness;

import java.math.BigInteger;
import java.nio.ByteBuffer;

/**
 * This is an implementation of a pseudorandom number based on a paper written
 * by L. Blum, M. Blum and M. Shub in 1982. The BBS (or X<sup>2</sup>-mod-N)
 * generator is proved to be as secure as the factorization of the Modulus
 * (which is a 1024 bit number).
 * <p>
 * The generator works in three steps:
 * <ol>
 * <li>The generator uses an internal 200 bit seed, so it is inefficient to do
 * something like a "brute force" attack (i.e. enumerate all possible seeds).
 * 
 * <li>In order to generate the parameters used during the generation, the
 * internal seed is expanded using a Linear Congruential Generator (LCG). This
 * generator is not secure in a cryptographical manner, but as no output of the
 * (LCG) is visible to the outside world, this is no problem. The parameters are
 * the seed X and the modulus N which is the product of two different prime
 * numbers P,Q of equal bit length. N is at least a 1024 bit number. The
 * parameters are generated after the instantiation and after each call to
 * reseed.
 * <li>Using these parameters, the generator iteratively determines a new X by
 * raising X to the power of 2 modulo N. During each iteration the
 * log<SUB><SMALL>2</SMALL></SUB>(|N|)-least-significant bits of the binary
 * representation of X are collected and form the output of the generator.
 * </ol>
 * 
 * @see
 * 
 * @author Marcus Lippert
 * @author Martin During
 * @author Anton Kabysh
 */
class BBS extends CryptorandomnessEngine {

	/**
	 * The security parameter is (in this case) the minimal bit length of the
	 * binary representation of the modulus
	 */
	private static final int SECURITY_PARAMETER = 1024;

	private static final int CERTAINTY = 10;

	/**
	 * Some numeric constants
	 */
	private static final BigInteger CONST_2 = BigInteger.valueOf(2);
	private static final BigInteger CONST_3 = BigInteger.valueOf(3);
	private static final BigInteger CONST_4 = BigInteger.valueOf(4);
	private static final BigInteger CONST_5 = BigInteger.valueOf(5);
	private static final BigInteger CONST_7 = BigInteger.valueOf(7);
	private static final BigInteger CONST_11 = BigInteger.valueOf(11);
	private static final BigInteger CONST_13 = BigInteger.valueOf(13);
	private static final BigInteger CONST_17 = BigInteger.valueOf(17);
	private static final BigInteger CONST_19 = BigInteger.valueOf(19);
	private static final BigInteger CONST_23 = BigInteger.valueOf(23);

	/** The modulus used with the Linear Congruential Generator */
	private final BigInteger LCG_MODULUS = new BigInteger(
			"805464911080722516417453601008791849136329615762701082177197");

	/**
	 * Used with the Linear Congruential Generator (LCG_X=LCG_A * LCG_X + LCG_B)
	 */
	private final BigInteger LCG_A = new BigInteger(
			"7129718823414295026033436596773772714578900265841170538826");

	private final BigInteger LCG_B = new BigInteger(
			"675276940120214627441986171104851609581303133674533034328917");

	/**
	 * Number of bits which are generated per iteration. The value is set in the
	 * constructor.
	 */
	private int bitsPerRound;

	private BigInteger n;

	private BigInteger p;

	private BigInteger q;

	private BigInteger x = null;

	private BigInteger seed = null;

	public BBS() {

		// calculate the number of bits to be generated per iteration
		bitsPerRound = 0;
		for (int i = 0; i < 32; i++) {
			if ((SECURITY_PARAMETER & (1 << i)) != 0) {
				bitsPerRound = i;
			}
		}
		this.reset();
	}

	/**
	 * Modifies the seed of this random object in the following way:
	 * <ul>
	 * <li>If this method is called before the object is seeded, i.e it is the
	 * first call of this method and no bytes have been generated by this object
	 * yet, the seed is set in a way that entirely depends on the given
	 * parameter and therefore is reproducible.</li>
	 * <li>If this method is called to an object already seeded, the new seed
	 * depends on both the current inner state and the given parameter.</li>
	 * </ul>
	 * 
	 * @param newSeed
	 *            the byte array containing a new seed
	 */
	@Override
	protected void instantiate(ByteBuffer seedBytes) {
		seedBytes.rewind();
		byte[] bytes = bufferToArray(seedBytes);

		if (seed != null) { // if the object is already seeded
			// modify the seed by xor-ing the parameter to the seed,
			seed = (seed.xor(new BigInteger(1, bytes))).mod(LCG_MODULUS);
		} else { // otherwise
			// set it explicitly
			seed = (new BigInteger(1, bytes)).mod(LCG_MODULUS);
		}

		generateParameters();
	}

	private final void generateParameters() {
		byte[] buf;
		// bitlength of p
		int pBL;
		// bitlength of q
		int qBL;
		int add;

		// determine bit lengths of p and q
		if ((SECURITY_PARAMETER & 1) == 1) {
			pBL = 1 + (SECURITY_PARAMETER >> 1);
			qBL = pBL;
		} else {
			pBL = SECURITY_PARAMETER >> 1;
			qBL = 1 + pBL;
		}

		// generate prime p

		// create p-2 bits via lcg
		buf = lcg(pBL - 2);
		// create a FlexiBigInt p
		p = new BigInteger(1, buf);
		// shift left: the LSB is set explicitly
		p = p.shiftLeft(1);
		// ensure that it is a p-bit Number
		p = p.setBit(pBL - 1);
		// and that it is odd
		p = p.setBit(0);

		// ensure that it is congruent 3 mod 4
		if (((p.mod(CONST_4)).compareTo(CONST_3)) != 0) {
			p = p.add(CONST_2);
		}

		// test for small factors
		int zmod3 = p.mod(CONST_3).intValue();
		int zmod5 = p.mod(CONST_5).intValue();
		int zmod7 = p.mod(CONST_7).intValue();
		int zmod11 = p.mod(CONST_11).intValue();
		int zmod13 = p.mod(CONST_13).intValue();
		int zmod17 = p.mod(CONST_17).intValue();
		int zmod19 = p.mod(CONST_19).intValue();
		int zmod23 = p.mod(CONST_23).intValue();

		// repeat until p is prime
		while (!p.isProbablePrime(CERTAINTY)) {
			add = 0;
			// add 4 while small factors exist:
			do {
				// this is cheaper than modifying the FlexiBigInt directly (if
				// the loop is passed often)
				add += 4;
				// this is cheaper than using the probabilistic primality test
				// in de.flexiprovider.common.math.FlexiBigInt
				zmod3 = (zmod3 + 4) % 3;
				zmod5 = (zmod5 + 4) % 5;
				zmod7 = (zmod7 + 4) % 7;
				zmod11 = (zmod11 + 4) % 11;
				zmod13 = (zmod13 + 4) % 13;
				zmod17 = (zmod17 + 4) % 17;
				zmod19 = (zmod19 + 4) % 19;
				zmod23 = (zmod23 + 4) % 23;
			} while ((zmod3 == 0) || (zmod5 == 0) || (zmod7 == 0)
					|| (zmod11 == 0) || (zmod13 == 0) || (zmod17 == 0)
					|| (zmod19 == 0) || (zmod23 == 0));
			// change FlexiBigInt accordingly
			p = p.add(BigInteger.valueOf(add));
		}

		// generate prime q

		do {
			// create q-2 bits via lcg
			buf = lcg(qBL - 2);
			// and create a FlexiBigInt q
			q = new BigInteger(1, buf);
			// shift left: bit 0 is set explicitly
			q = q.shiftLeft(1);
			// make it odd
			q = q.setBit(0);
			// ensure that it has q bits
			q = q.setBit(qBL - 1);

			// ensure that is congruent 3 mod 4
			if ((q.mod(CONST_4)).compareTo(CONST_3) != 0) {
				q = q.add(CONST_2);
			}

			// test for small factors
			zmod3 = q.mod(CONST_3).intValue();
			zmod5 = q.mod(CONST_5).intValue();
			zmod7 = q.mod(CONST_7).intValue();
			zmod11 = q.mod(CONST_11).intValue();
			zmod13 = q.mod(CONST_13).intValue();
			zmod17 = q.mod(CONST_17).intValue();
			zmod19 = q.mod(CONST_19).intValue();
			zmod23 = q.mod(CONST_23).intValue();

			// repeat until q is prime
			while (!q.isProbablePrime(CERTAINTY)) {
				add = 0;
				// add 4 while small factors exist:
				do {
					add += 4;
					zmod3 = (zmod3 + 4) % 3;
					zmod5 = (zmod5 + 4) % 5;
					zmod7 = (zmod7 + 4) % 7;
					zmod11 = (zmod11 + 4) % 11;
					zmod13 = (zmod13 + 4) % 13;
					zmod17 = (zmod17 + 4) % 17;
					zmod19 = (zmod19 + 4) % 19;
					zmod23 = (zmod23 + 4) % 23;
				} while (zmod3 == 0 || zmod5 == 0 || zmod7 == 0 || zmod11 == 0
						|| zmod13 == 0 || zmod17 == 0 || zmod19 == 0
						|| zmod23 == 0);
				q = q.add(BigInteger.valueOf(add));
			}
			// n = q * p
			n = p.multiply(q);

		}
		// repeat until q!= p
		while (q.compareTo(p) == 0);

		// create seed for the BBS
		do {
			buf = lcg(n.bitLength());
			x = (new BigInteger(1, buf)).mod(n);
		} while ((x.compareTo(BigInteger.ZERO) == 0) || (x.compareTo(p) == 0)
				|| (x.compareTo(q) == 0));
	}

	/**
	 * This method implements a linear congruential generator to extend the seed
	 * of 200 Bits to a size needed with the BBS generator. Theese bits are used
	 * to generate the parameters p, q, and x. The bits generated by the lcg are
	 * not visible from outside. Hence lcg does not have to be a
	 * cryrographically secure generator.
	 * 
	 * @param bitLength
	 *            number of bits to be generated
	 * @result an array containing the generated bits. Depending on (bitLength
	 *         mod 8), the first byte will be padded with zero bits.
	 */
	private byte[] lcg(int bitLength) {
		int i, j;
		// create an array big enough to contain all bits
		byte[] result = new byte[(bitLength + 7) >> 3];
		// leftover bits
		int leftBits = bitLength & 7;

		// generate all full bytes
		for (i = result.length - 1; i >= (result.length - (bitLength >> 3)); i--) {
			result[i] = 0;
			for (j = 1; j < 256; j <<= 1) {
				// always output the lsb
				if (seed.testBit(0)) {
					result[i] |= j;
				}
				// and then change the seed
				seed = (LCG_A.add(LCG_B.multiply(seed))).mod(LCG_MODULUS);
			}
		}

		// if needed
		if (i == 0) {
			// generate a byte with the leftover bits
			for (j = 0; j < leftBits; j++) {
				if (seed.testBit(0)) {
					result[i] |= 1 << j;
				} else {
					result[i] &= 255 - (1 << j);
				}
				seed = (LCG_A.add(LCG_B.multiply(seed))).mod(LCG_MODULUS);
			}

			// and pad it with zero bits
			for (j = leftBits; j < 8; j++) {
				result[i] &= 255 - (1 << j);
			}
		}
		return result;
	}

	@Override
	public final int read(ByteBuffer buffer) {

		byte[] bytes = new byte[buffer.remaining()];
		// number of bits to be generated
		int numBits = bytes.length << 3;
		// bitmask of next bit to be set
		int aktResultBit = 1;
		// generated byte
		int aktResultByte = 0;
		// bit to be copied
		int aktSourceBit = 0;
		// number of bits processed
		int aktResult = 0;

		try {
			lock.lock();
			// clear first byte
			bytes[0] = 0;
			do {
				// if source-bit is set
				if (x.testBit(aktSourceBit++)) {
					// set corresponding bit in result-vector
					bytes[aktResultByte] += aktResultBit;
				}
				// shift left bitmask by one
				aktResultBit = aktResultBit << 1;

				// if bitsPerRound is reached
				if (aktSourceBit == bitsPerRound) {
					// reset counter,
					aktSourceBit = 0;
					// and generate new seed (sqare-mod-generator)
					x = (x.multiply(x)).mod(n);
				}

				// if a whole byte has been generated
				if (aktResultBit == 256) {
					// reset bitmask
					aktResultBit = 1;
					// and switch to next byte
					aktResultByte++;
					// if one more byte is left to do
					if (aktResultByte < bytes.length) {
						// clear it.
						bytes[aktResultByte] = 0;
					}
				}

				// next bit
				aktResult++;
			} // while still some bits are to be generated
			while (aktResult < numBits);

			buffer.put(bytes);
			return bytes.length - buffer.remaining() /* should be zero */;
		} finally {
			byteCounter += bytes.length - buffer.remaining();
			lock.unlock();
		}
	}

	@Override
	public final void close() {
		try {
			lock.lock();
			p = null;
			q = null;
		} finally {
			lock.unlock();
		}
	}

	@Override
	public final boolean isOpen() {
		return p == null;
	}

	@Override
	public final int seedlen() {
		return CSPRNG.BBS.seedlen.get();
	}

	@Override
	public final String toString() {
		return "CSPRNG.BBS";
	}

	@Override
	public int minlen() {
		return ONE_BYTE;
	}
}
