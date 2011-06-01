package org.randomness;

import java.io.Closeable;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.BitSet;
import java.util.ConcurrentModificationException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.Lock;

import javax.crypto.Cipher;

/**
 * List of implemented <i>Cryptographically Secure Pseudorandom Number
 * Generators</i> that produces random numbers with properties that make it
 * suitable for use in cryptography. A process (or data produced by a process)
 * is said to be <i>pseudorandom</i> when the outcome is deterministic, yet also
 * effectively random as long as the internal action of the process is hidden
 * from observation. For cryptographic purposes, “effectively” means “within the
 * limits of the intended cryptographic strength.” <br>
 * <h3 align="center"><i>PROVISIONAL API, WORK IN PROGRESS</i></h3>
 * <p>
 * A cryptographically strong random number minimally complies with the
 * statistical random number generator tests specified in <a
 * href="http://csrc.nist.gov/cryptval/140-2.htm"> <i>FIPS 140-2, Security
 * Requirements for Cryptographic Modules</i></a>, section 4.9.1. Additionally,
 * CSPRNG must produce non-deterministic output. Therefore any seed material
 * passed to a CSPRNG object must be unpredictable, and all CSPRNG output
 * sequences must be cryptographically strong, as described in <a
 * href="http://www.ietf.org/rfc/rfc1750.txt"> <i>RFC 1750: Randomness
 * Recommendations for Security</i></a>.
 * 
 * @author <a href="mailto:anton.kabysh@gmail.com">Anton Kabysh</a> (randomness
 *         adaptation)
 * @author <br>
 *         Daniel Dyer (uncommons-math AES Counter)
 * @author <br>
 *         Marcus Lippert, Martin During ({@linkplain CSPRNG#BBS Blum-Blum-Shub}
 *         generator)
 * @author <br>
 *         Benjamin Renaud, Josh Bloch, Gadi Guy ({@linkplain CSPRNG#NATIVE Java
 *         Native Generator})
 * @author <br>
 *         Chuck McManis, Benjamin Renaud, Andreas Sterbenz (Java
 *         {@linkplain CSPRNG#MD5 MD5} implementation)
 * @author <br>
 *         Roger Riggs, Benjamin Renaud, Andreas Sterbenz, Valerie Peng (Java
 *         {@linkplain CSPRNG#SHA1 SHA1}, {@linkplain CSPRNG#SHA2 SHA-256} and
 *         {@linkplain CSPRNG#SHA512 SHA-512} implementation)
 * @author <br>
 *         Doug Lea (idea and implementation of
 *         <code>java.util.concurrent.ThreadLocalRandom</code>)
 * @see <a
 *      href="http://download.oracle.com/javase/6/docs/technotes/guides/security/crypto/CryptoSpec.html">Java
 *      ™ Cryptography Architecture - (JCA) Reference Guide</a>
 * @see <a
 *      href="http://en.wikipedia.org/wiki/Comparison_of_cryptographic_hash_functions">Comparison
 *      of cryptographic hash functions</a> <p>
 * @see <a href="http://www.flexiprovider.de/">The FlexiProvider is a powerful
 *      toolkit for the Java Cryptography Architecture (JCA/JCE).</a>
 */
public enum CSPRNG /* implements Generator, Closeable */{
	/**
	 * Non-linear random number generator based on the <i>AES block cipher in
	 * counter mode</i>. Cipher increments counter before producing next random
	 * block.
	 * <p>
	 * <b>AES</b> is Advanced Encryption Standard as specified by NIST in a
	 * draft FIPS. Based on the Rijndael algorithm by Joan Daemen and Vincent
	 * Rijmen, AES is a 128-bit block cipher supporting keys of 128, 192, and
	 * 256 bits.<br>
	 * <p>
	 * The AES Cryptorandomness based on JCE algorithm:
	 * <b>AES/ECB/NoPadding</b>.<br>
	 * The DRBG Mechanisms Based on Block Ciphers <b>CTR_DRBG</b> specified in
	 * Section 10.2 of NIST 800-90 Special Publication (p. 45). This
	 * recommendations was used to construct underlying implementation of block
	 * {@link Cipher} <code>Cryptorandomness</code> in counter mode.
	 * <p>
	 * <b>The default key size is 16 bytes (128 bit).</b> Other allowed key
	 * length is 24 and 32 bytes. Key length can be configured to one of this
	 * values if it's specified key length is supported by underlying security
	 * provider. You can define maximum allowed key length on your platform (in
	 * bits) by calling:
	 * <p>
	 * <code>
	 *        int keySizeBits = Cipher.getMaxAllowedKeyLength("AES/ECB/NoPadding");
	 * </code>
	 * <p>
	 * <b>The output block length is equal to key length.</b>
	 * <p>
	 * Instances of this CSPRNG is internally buffered with buffer size equal to
	 * output block length.
	 * 
	 * @see <a
	 *      href="http://en.wikipedia.org/wiki/Advanced_Encryption_Standard">Advanced
	 *      Encryption Standard</a>
	 * 
	 */
	AES(16) {
		@Override
		public final Cryptorandomness newInstance() {
			return new CipherCryptorandomness("AES/ECB/NoPadding", //
					seedlen.get());
		}
	}, // Default seed size is 128, 192 or 256 bits
	/**
	 * The BBS (or X<sup>2</sup>-mod-N) generator based on a paper written by L
	 * Blum, M Blum and M Shub in 1982 and is proved to be as secure as the
	 * factorization of the Modulus (which is a 1024 bit number).
	 * <p>
	 * The generator works in three steps:
	 * <ol>
	 * <li>The generator uses an internal <b>25 bytes (200 bit) seed (not
	 * configurable)</b>, so it is inefficient to do something like a
	 * "brute force" attack (i.e. enumerate all possible seeds).
	 * 
	 * <li>In order to generate the parameters used during the generation, the
	 * internal seed is expanded using a Linear Congruential Generator (LCG).
	 * This generator is not secure in a cryptographical manner, but as no
	 * output of the (LCG) is visible to the outside world, this is no problem.
	 * The parameters are the seed X and the modulus N which is the product of
	 * two different prime numbers P,Q of equal bit length. N is at least a 1024
	 * bit number. The parameters are generated after the instantiation and
	 * after each call to reseed.
	 * <li>Using these parameters, the generator iteratively determines a new X
	 * by raising X to the power of 2 modulo N. During each iteration the
	 * log<SUB><SMALL>2</SMALL></SUB>(|N|)-least-significant bits of the binary
	 * representation of X are collected and form the output of the generator.
	 * </ol>
	 * 
	 * @see <a href="http://en.wikipedia.org/wiki/Blum_Blum_Shub">Wikipedia -
	 *      Blum Blum Shub generator</a>
	 * @see <a href="http://en.wikipedia.org/wiki/Integer_factorization">Integer
	 *      factorization</a>
	 * 
	 * @since 1986
	 */
	BBS(25) {
		@Override
		public final Cryptorandomness newInstance() {
			return new org.randomness.BBS();
		}
	}, // The generator uses an internal 200 bit seed
	/**
	 * Non-linear random number generator based on the <i>Blowfish block cipher
	 * in counter mode</i>. Cipher increments counter before producing next
	 * random block.
	 * <p>
	 * <b>Blowfish</b>: is a keyed, symmetric block cipher, designed in 1993 by
	 * Bruce Schneier and included in a large number of cipher suites and
	 * encryption products. Blowfish provides a good encryption rate in software
	 * and no effective cryptanalysis of it has been found to date. However, the
	 * {@linkplain CSPRNG#AES Advanced Encryption Standard} now receives more
	 * attention.<br>
	 * The DRBG Mechanisms Based on Block Ciphers <b>CTR_DRBG</b> specified in
	 * Section 10.2 of NIST 800-90 Special Publication. This recommendations was
	 * used to construct underlying implementation of block {@link Cipher}
	 * <code>Cryptorandomness</code> in counter mode.
	 * <p>
	 * The Blowfish Cryptorandomness based on JCE algorithm: <b>Blowfish</b>.
	 * <br>
	 * <p>
	 * <b>The default key size is 16 bytes (128 bit).</b> Other allowed key
	 * length is 24 and 32 bytes. Key length can be configured to one of this
	 * values. If it's specified key length is supported by underlying security
	 * provider. You can define maximum allowed key length on your platform (in
	 * bits) by calling:
	 * <p>
	 * <code>
	 *        int keySizeBits = Cipher.getMaxAllowedKeyLength("Blowfish");
	 * </code>
	 * <p>
	 * <b>The output block length is equal to key length.</b>
	 * <p>
	 * Instances of this CSPRNG is internally buffered with buffer size equal to
	 * output block length.
	 * 
	 * @see <a
	 *      href="http://en.wikipedia.org/wiki/Blowfish_%28cipher%29">Wikipedia
	 *      - Blowfish (cipher)</a>
	 * @see <a href="http://en.wikipedia.org/wiki/Bruce_Schneier">Wikipedia -
	 *      Bruce Schneier</a>
	 */
	BLOWFISH(16) {
		@Override
		public final Cryptorandomness newInstance() {
			return new CipherCryptorandomness("Blowfish", //
					seedlen.get());
		}
	},
	/**
	 * Non-linear random number generator based on the <i>MD5 cryptographic hash
	 * function in counter mode</i>. The MD5 hash function is used to compute an
	 * message digest from a internal state, seed and counter. Result output
	 * digest is used to update the internal state and as a random output. After
	 * cycle of operations, the seed is also updated.
	 * <p>
	 * It is an implementation of the RSA Data Security Inc. MD5 algorithm as
	 * described in RFC 1321.<br>
	 * The DRBG Mechanisms Based on Hash Functions <b>Hash_DRBG</b> specified in
	 * Section 10.1 of NIST 800-90 Special Publication (p. 34). This
	 * recommendations is used to construct underlying implementation of
	 * {@link MessageDigest} <code>Cryptorandomness</code> in counter mode.
	 * <p>
	 * This generator in default use the <code>MD5</code> implementation from
	 * <code>Sun</code>, as follows:
	 * <code>MessageDigest digest = MessageDigest.getInstance("MD5");</code> If
	 * this implementation of <code>MD5</code> message digest is not present in
	 * the system (throws <code>NoSuchAlgorithmException</code>), than used
	 * internal implementation.
	 * <p>
	 * <b>This generator uses at minimum 16 byte seed.</b> Seed size can be
	 * configured to arbitrary value not lower than default.
	 * <p>
	 * <b>The output block is 16 bytes.</b>
	 * <p>
	 * Instances of this CSPRNG is internally buffered with buffer size equal to
	 * output block length.
	 * 
	 * @see <a href="http://en.wikipedia.org/wiki/MD5">Wikipedia - MD5</a>
	 * @see <a href="http://tools.ietf.org/html/rfc1321">RFC 1321 - The MD5
	 *      Message-Digest Algorithm</a>
	 */
	MD5(16) {
		@Override
		public final Cryptorandomness newInstance() {
			return new DigestCryptorandomness("MD5", //
					seedlen.get());
		}
	},
	/**
	 * Provides a <i>native</i> cryptographically strong random number generator
	 * supported by Java Platform (default instance of
	 * <code>java.security.SecureRandom</code> ). The default instance of
	 * {@link SecureRandom} creates secure random number generator (RNG)
	 * implementing the default random number algorithm.
	 * <p>
	 * Traverses the list of registered security Providers, starting with the
	 * most preferred Provider. A new object encapsulating the SecureRandomSpi
	 * implementation from the first Provider that supports a SecureRandom (RNG)
	 * algorithm is returned. If none of the Providers support a RNG algorithm,
	 * then an implementation-specific default is returned.
	 * <p>
	 * This is a most commonly used generator, that should be work on the all
	 * platforms. This generator adapts himself to platform-specific properties.
	 * E.g. on Linux uses <code>/dev/random</code> or <code>/dev/urandom</code>.
	 * Usually it uses a <code>SHA1PRNG</code> instance based on
	 * <code>SHA1</code> hash function. <b>This generator uses at minimum a 20
	 * byte (160 bit) seed for this generator.</b> Seed size can be configured
	 * to arbitrary value such, that is no lower than default. This generator is
	 * used to seed itself, as in original <code>SecureRandom</code>, but seed
	 * bytes is processed by derivation function.
	 * 
	 * @see <a
	 *      href="http://www.docjar.com/html/api/sun/security/provider/SecureRandom.java.html">Open
	 *      JDK <code>sun.security.provider.SecureRandom</code>
	 *      implementation</a>
	 */
	NATIVE(20) {
		@Override
		public final Cryptorandomness newInstance() {
			// Reference to java.secure.SecureRandom
			return new SecureCryptorandomness();
		}
	},
	/**
	 * Non-linear random number generator based on the <i>SHA1 cryptographic
	 * hash function in counter mode</i>. The SHA1 hash function is used to
	 * compute an message digest from a internal state, seed and counter. Result
	 * output digest is used to update the internal state and as a random
	 * output. After cycle of operations, the seed is also updated.
	 * <p>
	 * Secure Hash Algorithm SHA1 developed by the National Institute of
	 * Standards and Technology along with the National Security Agency as
	 * described in FIPS 180-3.<br>
	 * The DRBG Mechanisms Based on Hash Functions <b>Hash_DRBG</b> specified in
	 * Section 10.1 of NIST 800-90 Special Publication (p. 34). This
	 * recommendations is used to construct underlying implementation of
	 * {@link MessageDigest} <code>Cryptorandomness</code> in counter mode.
	 * <p>
	 * This generator in default use the <code>SHA1</code> implementation from
	 * <code>Sun</code>, as follows:
	 * <code>MessageDigest digest = MessageDigest.getInstance("SHA1");</code> If
	 * this implementation is not present in the system (throws
	 * <code>NoSuchAlgorithmException</code>), than execution is stopped,
	 * throwing unchecked error (<code>InternalError</code>). Internal
	 * implementation of SHA1 message digest is not supported yet.
	 * <p>
	 * <b>SHA1 digest generator uses 55 byte (440 bits) seed</b>, as specified
	 * at NIST SP 800-80, Table 2: Definitions for Hash-Based DRBG Mechanisms.
	 * Seed size can be configured to arbitrary value not lower than default.
	 * <p>
	 * <b>The output block is 20 bytes.</b>
	 * <p>
	 * Instances of this CSPRNG is internally buffered with buffer size equal to
	 * output block length.
	 * 
	 * @see <a href="http://en.wikipedia.org/wiki/SHA-1">Wikipedia - SHA1</a>
	 * @see <a href=
	 *      "http://csrc.nist.gov/publications/fips/fips180-3/fips180-3_final.pdf"
	 *      >FIPS 180-3 - Secure Hash Standard (PDF)</a>
	 */
	SHA1(55) {
		@Override
		public final Cryptorandomness newInstance() {
			return new DigestCryptorandomness("SHA1", //
					seedlen.get());
		}
	}, //
	/**
	 * Non-linear random number generator based on the <i>SHA-256 cryptographic
	 * hash function in counter mode</i>. The SHA-256 hash function is used to
	 * compute an message digest from a internal state, seed and counter. Result
	 * output digest is used to update the internal state and as a random
	 * output. After cycle of operations, the seed is also updated.
	 * <p>
	 * Secure Hash Algorithm SHA-256 developed by the National Institute of
	 * Standards and Technology along with the National Security Agency as
	 * described in FIPS 180-3. <br>
	 * The DRBG Mechanisms Based on Hash Functions <b>Hash_DRBG</b> specified in
	 * Section 10.1 of NIST 800-90 Special Publication (p. 34). This
	 * recommendations is used to construct underlying implementation of
	 * {@link MessageDigest} <code>Cryptorandomness</code> in counter mode.
	 * <p>
	 * This generator in default use the <code>SHA2</code> implementation from
	 * <code>Sun</code>, as follows:
	 * <code>MessageDigest digest = MessageDigest.getInstance("SHA-256");</code>
	 * If this implementation is not present in the system (throws
	 * <code>NoSuchAlgorithmException</code>), than execution is stopped,
	 * throwing unchecked error (<code>InternalError</code>). Internal
	 * implementation of SHA2 hash function is not supported yet.
	 * <p>
	 * <b>SHA2 digest generator uses 55 byte (440 bits) seed</b>, as specified
	 * at NIST SP 800-80, Table 2: Definitions for Hash-Based DRBG Mechanisms.
	 * Seed size can be configured to arbitrary value not lower than default.
	 * <p>
	 * <b>The output block is 32 bytes.</b>
	 * <p>
	 * Instances of this CSPRNG is internally buffered (witout external
	 * Instances of this CSPRNG is internally buffered with buffer size equal to
	 * output block length.
	 * 
	 * @see <a href="http://en.wikipedia.org/wiki/SHA-2">Wikipedia - SHA2</a>
	 * @see <a href=
	 *      "http://csrc.nist.gov/publications/fips/fips180-3/fips180-3_final.pdf"
	 *      >FIPS 180-3 - Secure Hash Standard (PDF)</a>
	 */
	SHA2(55) {
		@Override
		public final Cryptorandomness newInstance() {
			return new DigestCryptorandomness("SHA-256", //
					seedlen.get());
		}
	},
	/**
	 * Non-linear random number generator based on the <i>SHA-512 cryptographic
	 * hash function in counter mode</i>. The SHA-512 hash function is used to
	 * compute an message digest from a internal state, seed and counter. Result
	 * output digest is used to update the internal state and as a random
	 * output. After cycle of operations, the seed is also updated.
	 * <p>
	 * Secure Hash Algorithm SHA-512 developed by the National Institute of
	 * Standards and Technology along with the National Security Agency <br>
	 * The DRBG Mechanisms Based on Hash Functions <b>Hash_DRBG</b> specified in
	 * Section 10.1 of NIST 800-90 Special Publication (p. 34). This
	 * recommendations is used to construct underlying implementation of
	 * {@link MessageDigest} <code>Cryptorandomness</code> in counter mode.
	 * <p>
	 * This generator in default use the <code>SHA-512</code> implementation
	 * from <code>Sun</code>, as follows:
	 * <code>MessageDigest digest = MessageDigest.getInstance("SHA-512");</code>
	 * If this implementation is not present in the system (throws
	 * <code>NoSuchAlgorithmException</code>), than execution is stopped,
	 * throwing unchecked error (<code>InternalError</code>). Internal
	 * implementation of SHA-512 hash function is not supported yet.
	 * <p>
	 * <b>SHA-512 digest generator uses 111 byte (888 bits) seed</b>, as
	 * specified at NIST SP 800-80, Table 2: Definitions for Hash-Based DRBG
	 * Mechanisms. Seed size can be configured to arbitrary value not lower than
	 * default.
	 * <p>
	 * <b>The output block is 64 bytes.</b>
	 * <p>
	 * Instances of this CSPRNG is internally buffered with buffer size equal to
	 * output block length.
	 * 
	 * @see <a href="http://en.wikipedia.org/wiki/SHA-2">Wikipedia - SHA2</a>
	 * @see <a
	 *      href="http://csrc.nist.gov/publications/fips/fips180-3/fips180-3_final.pdf">FIPS
	 *      180-3 - Secure Hash Standard (PDF)</a>
	 */
	SHA512(111) {
		@Override
		public final Cryptorandomness newInstance() {
			return new DigestCryptorandomness("SHA-512", //
					seedlen.get());
		}
	},

	/**
	 * VMPC ("Variably Modified Permutation Composition") is encryption
	 * technology designed by Bartosz Zoltak, publicly presented in 2004; The
	 * core of the technology is the VMPC one-way function, applied in an
	 * encryption algorithm - the <i>VMPC stream cipher</i>.
	 * <p>
	 * <b>VMPC one way function uses 64 byte (512 bits) seed.</b>
	 * 
	 * @see <a
	 *      href="http://en.wikipedia.org/wiki/Variably_Modified_Permutation_Composition">Wikipedia
	 *      - VMPC</a>
	 * @see <a href="http://www.vmpcfunction.com/">VMPC Home Page</a>
	 * 
	 * @since 2004
	 */
	VMPC(64) {
		@Override
		public final Cryptorandomness newInstance() {
			return new VMPC();
		}
	}, // 16 <= c <=64

	/**
	 * <h3><i>PROVISIONAL API, WORK IN PROGRESS</i></h3> Not implemented.
	 */
	FORTUNA(0) {
		@Override
		Cryptorandomness newInstance() {
			// TODO Auto-generated method stub
			return null;
		}
	};

	/**
	 * Synonym of {@linkplain CSPRNG#NATIVE NATIVE} algorithm which
	 * {@linkplain SecureRandom} is used.
	 */
	public static final CSPRNG SECURE_RANDOM = NATIVE;

	private CSPRNG(int defaultSeedValue) {
		seedlen = new AtomicInteger(defaultSeedValue);
		// SEED_SIZE = new Parameter(defaultSeedValue, "SEED_SIZE",
		// CSPRNG.class) {
		//
		// /*
		// * Configuration logic for SEED_SIZE value.
		// *
		// * The Configurable method configure() first set new value, and
		// * after call notifyChange. If new value is not apropriate, we must
		// * restore previous (or default value) calling
		// * Configurable.configure() method wiht previous value and after
		// * throws an exception messadge.
		// */
		// @Override
		// protected void notifyChange(Integer oldValue, Integer newValue)
		// throws UnsupportedOperationException {
		//
		// // verify
		// switch (CSPRNG.this) {
		//
		// case AES:
		// testCipher("AES/ECB/NoPadding", oldValue, newValue);
		// return;
		// case BLOWFISH:
		// testCipher("Blowfish", oldValue, newValue);
		// return;
		//
		// case MD5:
		// case NATIVE:
		// case SHA1:
		// case SHA2:
		// case SHA512:
		// case VMPC:
		// final int val = newValue.intValue();
		//
		// // any value, greater than default is allowed.
		// if (val >= getDefault().intValue()) {
		// super.notifyChange(oldValue, newValue); // ok
		// return;
		// } else
		// Configurable.configure(this, oldValue); // restore
		//
		// // previous value is restored, throw an exception.
		// throw new UnsupportedOperationException(
		// "Unsupported. Seed size for "
		// + CSPRNG.this.toString()
		// + " PRNG is lower than default.");
		//
		// default:
		//
		// if (newValue.intValue() != getDefault().intValue())
		// Configurable.configure(this, oldValue); // restore
		// else
		// throw new UnsupportedOperationException(
		// "Unsupported. Seed Size of "
		// + CSPRNG.this.toString()
		// + " CSPRNG can't be configured.");
		//
		// }
		// }
		//
		// // for cipher we test maximum allowed key length
		// private final void testCipher(String algorithm, int oldVal,
		// int newVal) {
		//
		// Integer keySize = null;
		// try {
		// keySize = Cipher.getMaxAllowedKeyLength(algorithm) / 8;
		// } catch (Exception e) {
		// // hide
		// }
		// String msg = null;
		//
		// // is one from allowed keys
		// if (Arrays.binarySearch(CIPHER_KEYS, newVal) != -1) {
		// // is lower than Max Allowed key length
		// if (keySize != null)
		// if (newVal <= keySize.intValue()) {
		//
		// super.notifyChange(oldVal, newVal);
		// return;
		// } else {
		// msg = "New seed value is greater than Max Allowed Key Length - "
		// + keySize;
		// }
		//
		// // no info about Max Allowed key length
		// if (msg == null) {
		// // try to change
		// super.notifyChange(oldVal, newVal);
		// }
		// } else {
		// msg = "New seed value ("
		// + newVal
		// + ") is not from set of allowed cipher keys: [16, 24, 32] bytes.";
		// }
		//
		// // some errors, value can't be configured.
		// if (msg != null) {
		// Configurable.configure(this, oldVal); // restore
		//
		// // previous value is restored, throw an exception.
		// throw new UnsupportedOperationException(
		// "Unsupported. Illegal seed value for "
		// + CSPRNG.this.toString() + " CSPRNG: "
		// + msg);
		// }
		// }
		// };

	}

	final AtomicInteger seedlen;
	/**
	 * Synonym of {@linkplain CSPRNG#AES AES} algorithm.
	 */
	public static final CSPRNG RIJNDAEL = AES;

	/**
	 * Define approprate cipher keys.
	 */
	private static final int[] CIPHER_KEYS = { 16/* 128 bits */, 24/* 192 bits */,
			32 /* 256 bits */};

	/**
	 * Determine maximum length of <i>entropy input</i> string produced by
	 * <b>entropy function</b> in bytes; <b>default value</b> -
	 * <code>1024</code> bytes. The default {@link Cryptorandomness}
	 * implementation uses a hash based <i>derivation function</i>.
	 * <p>
	 * The <i>max_length</i> recomendations:
	 * <ul>
	 * <li>
	 * NIST SP 800-90 - Table 4: Definitions for the Dual_EC_DRBG, p. 58. : 1024
	 * bytes
	 * <li>
	 * NIST SP 800-90 - Table 3: Definitions for CTR_DRBG DRBG Mechanisms
	 * <ul>
	 * <li>
	 * If a derivation function is used: no greater than 2<sup>35</sup> bytes
	 * <li>
	 * If a derivation function is not used: <code>max_length == seedlen</code>,
	 * </ul>
	 * <li>
	 * NIST SP 800-90 - Table 2: Definitions for Hash-Based DRBG Mechanisms: no
	 * greater than 2<sup>35</sup> bytes
	 * </ul>
	 */
	public static final AtomicInteger MAX_ENTROPY_INPUT_LENGTH = new AtomicInteger(
			1024) {
		public String toString() {
			return "MAX_ENTROPY_INPUT_LENGTH";
		};
	};
	/**
	 * Determine maximum <i>personalization string</i> length in bytes;
	 * <b>default value</b> - <code>1024</code> bytes.<br>
	 * The default {@link Cryptorandomness} implementation uses a hash based
	 * <i>derivation function</i>.
	 * <p>
	 * The <i>max_personalization_string_length</i> recomendations:
	 * <ul>
	 * <li>
	 * NIST SP 800-90 - Table 4: Definitions for the Dual_EC_DRBG, p. 58. : 1024
	 * bytes
	 * <li>
	 * NIST SP 800-90 - Table 3: Definitions for CTR_DRBG DRBG Mechanisms
	 * <ul>
	 * <li>
	 * If a derivation function is used: no greater than 2<sup>35</sup> bytes
	 * <li>
	 * If a derivation function is not used: <code>max_length == seedlen</code>,
	 * </ul>
	 * <li>
	 * NIST SP 800-90 - Table 2: Definitions for Hash-Based DRBG Mechanisms: no
	 * greater than 2<sup>35</sup> bytes
	 * </ul>
	 */
	public static final AtomicInteger MAX_PERSONALIZATION_STRING_LENGTH = new AtomicInteger(
			1024) {

		public String toString() {
			return "MAX_ENTROPY_INPUT_LENGTH";
		};
	};

	/**
	 * Returns a new <code>Cryptorandomness</code> object that implements the
	 * specified Cryptosecure Random Number Generator algorithm.
	 * 
	 * @return a new Cryptorandomness generator
	 */
	abstract Cryptorandomness newInstance();

	/**
	 * Create's new instance of specified <i>Cryptographically Random Number
	 * Generator</i> wiht default configurable parameters. This method return's
	 * <code>null</code> if specified generator is not supported at this moment
	 * (e.g. no enougth entropy, or algorithm is not present is the system).
	 * 
	 * @return a new <code>Cryptorandomness</code> generator (created wiht
	 *         default parameters), or <code>null</code> if this generator is
	 *         not supported by platform at this time.
	 * 
	 * @see Cryptorandomness#from(CSPRNG)
	 */
	public final Cryptorandomness defaultInstance() {
		// LocalConfigurable<Integer> seedSize = (LocalConfigurable<Integer>)
		// SEED_SIZE;
		// LocalConfigurable<Integer> maxEI = (LocalConfigurable<Integer>)
		// MAX_ENTROPY_INPUT_LENGTH;
		// LocalConfigurable<Integer> maxPS = (LocalConfigurable<Integer>)
		// MAX_PERSONALIZATION_STRING_LENGTH;
		//
		// try {
		// LocalContext.enter();
		//
		// // configure to default value
		// seedSize.set(SEED_SIZE.getDefault());
		// maxEI.set(MAX_ENTROPY_INPUT_LENGTH.getDefault());
		// maxPS.set(MAX_PERSONALIZATION_STRING_LENGTH.getDefault());
		//
		// // create instance
		// return newInstance();
		//
		// } catch (Throwable t) {
		// // hide
		// } finally {
		// LocalContext.exit(); // restore current values
		// }
		//
		// // not supported
		// return null;
		return newInstance();
	}

	// /**
	// * Internal instance of this CSPRNG.
	// */
	// private Cryptorandomness instance;
	//
	// /**
	// * Resets internal instance of this CSPRNG. If internal instance is not
	// * previously created (e.g. no such entropy, or algorithm is not present
	// is
	// * the system), than it try to re-create this again (without throwing any
	// * exceptions).
	// */
	// public final void reset() {
	// if (instance == null) {
	// try {
	//
	// instance = defaultInstance();
	//
	// } catch (Throwable t) {
	// // hide
	// }
	// } else
	// instance.reset();
	// }

	//
	// // ///////////////////////////////////////////////////////////////
	// // ////////////////// GENERATE METHODS ///////////////////////////
	// // ///////////////////////////////////////////////////////////////
	// /**
	// * Return's next generated cryptorandom <code>int</code> (32-bit) value.
	// *
	// * @see <a
	// *
	// href="http://java.sun.com/docs/books/jls/third_edition/html/typesValues.html#4.2.1">JLS
	// * - 4.2.1 Integral Types and Values</a>
	// *
	// * @return newly generated cryptorandom <code>int</code> value.
	// *
	// * @throws NullPointerException
	// * if generator of current type is not supported by system (e.g.
	// * {@link #AES} with 256 bit key).
	// */
	// public final int nextInt() {
	// if (instance == null)
	// instance = defaultInstance();
	//
	// return instance.nextInt();
	// }
	//
	// /**
	// * Return's next generated, uniformly distributed cryptorandom
	// * <code>boolean</code> (1-bit) value.
	// * <p>
	// * It is important to remember, that <code>boolean</code> values are hold
	// in
	// * platform dependent way (depends from JVM). For large
	// <code>boolean</code>
	// * arrays better to use something like {@link BitSet}.
	// *
	// * @see <a href="http://en.wikipedia.org/wiki/Bit">Wikipedia - Bit</a>
	// * @see <a
	// *
	// href="http://java.sun.com/docs/books/jls/third_edition/html/typesValues.html#4.2.5">JLS
	// * - 4.2.5 The boolean Type and boolean Values</a>
	// * @return newly generated cryptorandom boolean value.
	// *
	// * @throws NullPointerException
	// * if generator of current type is not supported by system (e.g.
	// * {@link #AES} with 256 bit key).
	// */
	// @Override
	// public final boolean nextBoolean() {
	// if (instance == null)
	// instance = defaultInstance();
	//
	// return instance.nextBoolean();
	// }
	//
	// /**
	// * Return's next generated, cryptorandom <code>byte</code> (8-bit) value.
	// * <p>
	// * There are {@link #VMPC} and {@link #BBS} generators, essentially
	// * producing <code>byte</code> per one iteration.
	// *
	// * @see <a href="http://en.wikipedia.org/wiki/Byte">Wikipedia - Byte</a>
	// * @see <a
	// *
	// href="http://java.sun.com/docs/books/jls/third_edition/html/typesValues.html#4.2.1">JLS
	// * - 4.2.1 Integral Types and Values</a>
	// * @return newly generated cryptorandom byte value.
	// *
	// * @throws NullPointerException
	// * if generator of current type is not supported by system (e.g.
	// * {@link #AES} with 256 bit key).
	// */
	// @Override
	// public final byte nextByte() {
	// if (instance == null)
	// instance = defaultInstance();
	//
	// return instance.nextByte();
	// }
	//
	// /**
	// * Return's next generated, uniformly distributed random <code>char</code>
	// * (unsigned 16-bit) value (typically from <code>nextShort</code> value
	// * casting to <code>char</code> ).
	// *
	// * @see <a
	// *
	// href="http://java.sun.com/docs/books/jls/third_edition/html/typesValues.html#4.2.1">JLS
	// * - 4.2.1 Integral Types and Values</a>
	// *
	// * @return newly generated random <code>char</code> value.
	// *
	// * @throws NullPointerException
	// * if generator of current type is not supported by system (e.g.
	// * {@link #AES} with 256 bit key).
	// */
	// @Override
	// public final char nextChar() {
	// if (instance == null)
	// instance = defaultInstance();
	//
	// return instance.nextChar();
	// }
	//
	// /**
	// * Return's next generated, uniformly distributed random
	// <code>double</code>
	// * (64-bit) value between <code>0.0</code> and <code>1.0</code> (taking
	// most
	// * significant 53 bits to mantissa).
	// *
	// * @see <a
	// *
	// href="http://java.sun.com/docs/books/jls/third_edition/html/typesValues.html#4.2.3">JLS
	// * - 4.2.3 Floating-Point Types, Formats, and Values</a>
	// * @see <a href="http://en.wikipedia.org/wiki/IEEE_754-2008">Wikipedia -
	// * IEEE 754</a>
	// * @return newly generated random <code>double</code> value.
	// *
	// * @throws NullPointerException
	// * if generator of current type is not supported by system (e.g.
	// * {@link #AES} with 256 bit key).
	// */
	// @Override
	// public final double nextDouble() {
	// if (instance == null)
	// instance = defaultInstance();
	//
	// return instance.nextDouble();
	// }
	//
	// /**
	// * Return's next generated, uniformly distributed random
	// <code>float</code>
	// * (32-bit) value between <code>0.0</code> and <code>1.0</code> (taking
	// most
	// * significant 24 bits to mantissa from <code>nextInt</code> value).
	// * <p>
	// * There is no generators essentially generating random <code>float</code>
	// * values per one, but appropriate to <code>nextInt</code> generators
	// tends
	// * to be good converting <code>int</code> to <code>float</code>.
	// *
	// * @see <a
	// *
	// href="http://java.sun.com/docs/books/jls/third_edition/html/typesValues.html#4.2.3">JLS
	// * - 4.2.3 Floating-Point Types, Formats, and Values</a>
	// * @see <a href="http://en.wikipedia.org/wiki/IEEE_754-2008">Wikipedia -
	// * IEEE 754</a>
	// *
	// * @return newly generated random <code>float</code> value.
	// *
	// * @throws NullPointerException
	// * if generator of current type is not supported by system (e.g.
	// * {@link #AES} with 256 bit key).
	// */
	// @Override
	// public final float nextFloat() {
	// if (instance == null)
	// instance = defaultInstance();
	//
	// return instance.nextFloat();
	// }
	//
	// /**
	// * Return's next generated, uniformly distributed random <code>long</code>
	// * (64-bit) value.
	// *
	// * @see <a
	// *
	// href="http://java.sun.com/docs/books/jls/third_edition/html/typesValues.html#4.2.1">JLS
	// * - 4.2.1 Integral Types and Values</a>
	// *
	// * @return newly generated true random <code>long</code> value.
	// *
	// * @throws NullPointerException
	// * if generator of current type is not supported by system (e.g.
	// * {@link #AES} with 256 bit key).
	// */
	// @Override
	// public final long nextLong() {
	// if (instance == null)
	// instance = defaultInstance();
	//
	// return instance.nextLong();
	// }
	//
	// /**
	// * Return's next generated true random <code>short</code> (16-bit) value
	// * (typically from <code>nextInt</code> value returned two most
	// significant
	// * bytes).
	// *
	// * @see <a
	// *
	// href="http://java.sun.com/docs/books/jls/third_edition/html/typesValues.html#4.2.1">JLS
	// * - 4.2.1 Integral Types and Values</a>
	// *
	// * @return newly generated true random <code>short</code> value.
	// *
	// * @throws NullPointerException
	// * if generator of current type is not supported by system (e.g.
	// * {@link #AES} with 256 bit key).
	// *
	// */
	// @Override
	// public final short nextShort() {
	// if (instance == null)
	// instance = defaultInstance();
	//
	// return instance.nextShort();
	// }
	//
	// /**
	// * Generates random block of cryptorandom bytes and places them into a
	// * user-supplied byte array.
	// * <p>
	// * There are several <code>CSPRNG</code> generators, essentially producing
	// * block output:
	// * <ol>
	// * <li> {@link CSPRNG#AES} - blocks per 16 bytes (specified by AES key
	// size),
	// * <li> {@link CSPRNG#BLOWFISH} - blocks per 16 bytes (specified by
	// Blowfish
	// * key size).
	// * <li> {@link #MD5} - blocks per 16 bytes
	// * <li> {@link CSPRNG#BBS} - requested block (one byte per iteration),
	// * <li> {@link CSPRNG#SHA1} ({@link #NATIVE}), {@link CSPRNG#SHA2} and
	// * {@link CSPRNG#SHA512} - blocks per 20, 32 and 64 bytes respectively.
	// * </ol>
	// *
	// * @param bytes
	// * - the byte array to fill with random bytes
	// *
	// * @throws NullPointerException
	// * if generator of current type is not supported by system (e.g.
	// * {@link #AES} with 256 bit key).
	// */
	// @Override
	// public final void read(byte[] bytes) {
	// if (instance == null)
	// instance = defaultInstance();
	//
	// instance.read(bytes);
	// }
	//
	// /**
	// * Returns a <code>double</code> value with a positive sign, greater than
	// or
	// * equal to <code>0.0</code> and less than <code>1.0</code> (as in
	// * <code>java.lang.Math</code>). Returned values are chosen randomly with
	// * (approximately) uniform distribution from that range.
	// * <p>
	// * The same as <code>nextDouble</code>.
	// *
	// * @return a random double greater than or equal to 0.0 and less than 1.0.
	// */
	// public final double random() {
	// if (instance == null)
	// instance = defaultInstance();
	//
	// return instance.nextDouble();
	// }

	/**
	 * Returns a <b>unique</b> CSPRNG generator isolated to the current thread
	 * (<i>thread local random</i>). An attempt to use this instance from
	 * annoter thread will throw {@link ConcurrentModificationException}.
	 * <p>
	 * Usages of this class should typically be of the form:
	 * {@code CSPRNG.XXX.current().nextX(...)} (where {@code XXX} - one of
	 * implemented CSPRNG generators, and {@code X} is {@code Int}, {@code Long}
	 * , etc). When all usages are of this form, it is never possible to
	 * accidently share a <i>thread local random</i> across multiple threads.
	 * <p>
	 * The thread local random instance is unique for parent thread, so locality
	 * can be cheked as:
	 * 
	 * <pre>
	 * public boolean isThreadLocal(Randomness rnd) {
	 * 	return CSPRNG.XXX.current() == rnd;
	 * }
	 * </pre>
	 * 
	 * where {@code XXX} - one of implemented CSPRNG generators
	 * 
	 * @return the thread local instance of CSPRNG for current thread.
	 * @see ThreadLocal
	 * @see <br>
	 *      PRNG#current() Thread local for Pseudorandomness,
	 * @see <br>
	 *      TRNG#current() Thread-local for Truerandomness.
	 */
	// Fix to 1.7;
	public Cryptorandomness current() {
		return localRandom.get();
	}

	/**
	 * The actual ThreadLocal
	 */
	private final ThreadLocal<Cryptorandomness> localRandom = new ThreadLocal<Cryptorandomness>() {
		protected Cryptorandomness initialValue() {
			return defaultInstance();
		}
	};

	// /**
	// * Checks whatever or not this cryptosecure generator is allowed by
	// * underlying system (e.g. security restrictions).
	// * <p>
	// * For every platform designed own best {@linkplain #NATIVE native}
	// * cryptosecure generator which works well.
	// *
	// * <pre>
	// * Cryptorandomness crypto = null;
	// * CSPRNG.AES.SEED_SIZE.set(256); // possibly restricted
	// * if (CSPRNG.AES.isSupported()) {
	// * crypto = Cryptorandomness.from(AES);
	// * } else
	// * crypto = CSPRNG.NATIVE.current();
	// * </pre>
	// *
	// * @see TRNG#isSupported()
	// *
	// * @return <code>true</code> if generators of this type can be
	// instantiated
	// * on this platform, <code>false</code> otherwise.
	// */
	// public boolean isSupported() {
	//
	// return defaultInstance() != null;
	// }
	//
	// /**
	// * Closes this PRNG and releases any system resources associated with it;
	// * Any currently running generate function will be gracefully interrupted.
	// * If the stream is already closed then invoking this method has no
	// effect.
	// */
	// @Override
	// public void close() {
	// if (instance != null)
	// instance.close();
	// }

	/**
	 * Returns the <i>seed length</i> used by underlying CSPRNG algorithm in
	 * bytes. The minimum <i>seed length</i> depends on the CSPRNG mechanism and
	 * the <i>security strength</i> required by the consuming application.
	 * 
	 * 
	 * <p>
	 * <b>Note:</b> The default
	 * {@link Cryptorandomness#getEntropyInput(int, int, int)} implementation
	 * specify that <i>min_length</i> of required entropy shold not be greater
	 * than <i>max_length</i> constant. In other words, maximum
	 * {@link CSPRNG#seedlen} value is limited by
	 * {@link CSPRNG#MAX_ENTROPY_INPUT_LENGTH} value, when
	 * {@link Cryptorandomness#getEntropyInput(int, int, int)} function is
	 * called.
	 * <p>
	 * <b>Predefined values:</b>
	 * <table border="0" cellspacing="0">
	 * <th>Generator
	 * <th>Seed size
	 * <tr>
	 * <td>{@linkplain CSPRNG#AES AES}
	 * <td>16 bytes
	 * <td>Configurable: 16, 24, 32 bytes seed, if supported by platform
	 * <tr>
	 * <td>{@linkplain CSPRNG#BBS BBS}
	 * <td>25 bytes
	 * <td>Not configurable
	 * <tr>
	 * <td>{@linkplain CSPRNG#BLOWFISH BLOWFISH}
	 * <td>16 bytes
	 * <td>Configurable: 16, 24, 32 bytes seed, if supported by platform
	 * <tr>
	 * <td>{@linkplain CSPRNG#MD5 MD5}
	 * <td>16 bytes
	 * <td>Configurable (any value greater than default)
	 * <tr>
	 * <td>{@linkplain CSPRNG#NATIVE NATIVE}
	 * <td>20 bytes
	 * <td>Configurable (any value greater than default)
	 * <tr>
	 * <td>{@linkplain CSPRNG#SHA1 SHA1}
	 * <td>55 bytes
	 * <td>Configurable (any value greater than default)
	 * <tr>
	 * <td>{@linkplain CSPRNG#SHA2 SHA2}
	 * <td>55 bytes
	 * <td>Configurable (any value greater than default)
	 * <tr>
	 * <td>{@linkplain CSPRNG#SHA512 SHA-512}
	 * <td>111 bytes
	 * <td>Configurable (any value greater than default)
	 * <tr>
	 * <td>{@linkplain CSPRNG#VMPC VMPC}
	 * <td>64 bytes
	 * <td>Configurable (any value greater than default)
	 * </table>
	 * 
	 * @return return default initial seed length for particular CSPRNG in
	 *         bytes.
	 */
	public int seedlen() {
		return seedlen.get();
	}

	/**
	 * Checks whatever or not this CSPRNG is acessible on current platform.
	 * 
	 * @return <code>true</code> if generators of this type can be instantiated
	 *         on this platform, <code>false</code> otherwise.
	 */
	public boolean isSupported() {

		return defaultInstance() != null;
	}

}
