package org.randomness;

import java.math.BigInteger;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.channels.NonReadableChannelException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.SecureRandomSpi;

/**
 * This class specifies techniques for the compute <i>cryptographically
 * secure</i> bits deterministically using an underlying algorithm that, if an
 * adversary does not know the entropy input, then he can’t tell the difference
 * between the pseudorandom bits and a stream of truly random bits, let alone
 * predict any of the pseudorandom bits. This class of RBGs is known as
 * Cryptographically Secure (Determenistic) Pseudorandom Bit (or Number)
 * Generator (CSPRBG).
 * <p>
 * The requirements of an ordinary PRNG are also satisfied by a
 * cryptographically secure PRNG, but the reverse is not true. Such properties
 * of CSPRNG's make it suitable for use in cryptography for key, password,
 * nonce, salt generation. The output of CSPRBG's is never repeatable. <br>
 * <h3 align="center"><i>PROVISIONAL API, WORK IN PROGRESS</i></h3>
 * <h3>TODO:</h3>
 * <ol>
 * <li>Interruptible generation
 * <li>Support of selectable, nonblocking and asynchronous reading
 * <li>Full cryptorandomness model (incl full version of NIST 800-90)
 * <li>Secure Hex Strings
 * <li>Auto reseeding (limitations, probablistic reseeding, time-pereodic
 * resseeding).
 * <li>asynchronous escape
 * <li>Full integration with JCE
 * <li>Internal implementation of any message digest.
 * </ol>
 * <h3>
 * General requirements of CSPRNG from NIST 800-90 is:</h3>
 * <p>
 * Term <b>Shall</b> is used to indicate a <i>strong</i> requirement of NIST
 * 800-90 Recommendation.<br>
 * Term <b>Should</b> is used to indicate a <i>highly</i> desirable feature for
 * a CSPRNG mechanism that is not necessarily required by NIST 800-90
 * Recommendation.
 * <ul>
 * <li>The entropy input and the seed <b>shall</b> be kept secret. The secrecy
 * of this information provides the basis for the security of the CSPRNG.
 * <li>
 * The entropy input <b>shall</b> have entropy that is equal to or greater than
 * the <i>security strength</i> of the instantiation.
 * <li>
 * At a minimum, the entropy input <b>shall</b> provide the amount of entropy
 * requested by the RNG mechanism.
 * <li>
 * The information <b>should</b> be checked for validity when possible
 * <li>
 * A CSPRNG <b>shall</b> be instantiated prior to the generation of output by
 * the CSPRNG.
 * <li>
 * When a CSPRNG is used to generate pseudorandom bits, a seed <b>shall</b> be
 * acquired prior to the generation of output bits by the CSPRNG.
 * <li>
 * Entropy input <b>shall</b> always be used in the construction of a seed, a
 * nonce <b>shall</b> be used, a personalization string <b>should</b> also be
 * used.
 * <li>
 * The personalization string <b>should</b> be unique for all instantiations of
 * the same CSPRNG mechanism type.
 * <li>The internal state <b>shall</b> be protected at least as well as the
 * intended use of the pseudorandom output bits requested by the consuming
 * application.
 * <li>
 * The entropy input and the resulting seed <b>shall</b> be handled in a manner
 * that is consistent with the security required for the data protected by the
 * consuming application.
 * <li>
 * The entropy input and seed that is used to initialize one instantiation of a
 * CSPRNG <b>shall not</b> be intentionally used to reseed the same
 * instantiation or used as the entropy input and seed for another CSPRNG
 * instantiation. The seed used by a CSPRNG and the entropy input used to create
 * that seed <b>shall not</b> intentionally be used for other purposes.
 * <li>
 * Each CSPRNG instantiation <b>shall</b> have its own internal state. The
 * internal state for one CSPRNG instantiation <b>shall not</b> be used as the
 * internal state for a different instantiation.
 * <li>
 * The CSPRNG internal state and the operation of the CSPRNG mechanism functions
 * <b>shall</b> only be affected according to the CSPRNG mechanism
 * specification.
 * <li>
 * A consuming application <b>should</b> check the CSPRNG to determine that the
 * CSPRNG has been correctly instantiated.
 * <li>
 * When CSPRNG mechanism functions are distributed, appropriate mechanisms
 * <b>shall</b> be used to protect the confidentiality and integrity of the
 * internal state or parts of the internal state that are transferred between
 * the distributed CSPRNG mechanism sub-boundaries. The confidentiality and
 * integrity mechanisms and security strength <b>shall</b> be consistent with
 * the data to be protected by the CSPRNG’s consuming application (see SP
 * 800-57).
 * </ul>
 * 
 * <h3>CSPRNG mechanisms</h3>
 * A CSPRNG mechanism uses an algorithm (a CSPRNG algorithm) that produces a
 * sequence of bits from an initial value that is determined by a seed that is
 * determined from the entropy input. Once the seed is provided and the initial
 * value is determined, the CSPRNG is said to be instantiated. Because of the
 * deterministic nature of the process, a CSPRNG is said to produce pseudorandom
 * bits, rather than random bits. The seed used to instantiate the CSPRNG must
 * contain sufficient entropy to provide an assurance of randomness. If the seed
 * is kept secret, and the algorithm is well designed, the bits output by the
 * CSPRNG will be unpredictable, up to the instantiated security strength of the
 * CSPRNG.
 * <p>
 * The CSPRNG mechanism functions handle the CSPRNG’s internal state. The CSPRNG
 * mechanisms in this class have five separate functions:
 * <ol>
 * <li>
 * The {@linkplain Cryptorandomness#reset() instantiate function} acquires
 * entropy input and may combine it with a {@linkplain Cryptorandomness#nonce()
 * nonce} and a <i>personalization string</i> to create a seed from which the
 * initial internal state is created.</li>
 * <li>
 * The {@linkplain Cryptorandomness#read(ByteBuffer) generate function}
 * generates pseudorandom bits upon request, using the current internal state,
 * and generates a new internal state for the next request.</li>
 * <li>
 * The {@linkplain Cryptorandomness#reseed(ByteBuffer) reseed function} acquires
 * new entropy input and combines it with the current internal state and any
 * additional input that is provided to create a new seed and a new internal
 * state.</li>
 * <li>
 * The {@linkplain Cryptorandomness#close() uninstantiate function} zeroizes
 * (i.e., erases) the internal state.</li>
 * <li>
 * The health test function determines that the CSPRNG mechanism continues to
 * function correctly (optional).
 * <ul>
 * In cryptography, we will need certain high­quality PRBGs so that it is
 * computationally infeasible to predict the generated numbers. There are two
 * definitions of what it means for a PRBG to be cryptographically strong:
 * passing all polynomial­ time statistic tests and passing the <a
 * href="http://en.wikipedia.org/wiki/Next-bit_test">next-bit test</a>. A PRBG
 * is said to be cryptographically strong if it passes the next­bit test. That
 * means that for any polynomial time adversary required a <i>security
 * strength</i> number of operations.
 * </ul>
 * 
 * </ol>
 * This functions is implemented as much as possible close to NIST 800-90
 * Recommendations. A function need not be implemented using such envelopes, but
 * the function <b>shall</b> have equivalent functionality. The detailed
 * description can be found in documentation to CSPRNG mechanism functions.
 * Specification of this class based on full version of NIST 800-90 special
 * publication.
 * 
 * 
 * 
 * @see <a
 *      href="http://en.wikipedia.org/wiki/Cryptographically_secure_pseudo-random_number_generator"
 *      >Wikipedia - Cryptographically secure pseudorandom number generator</a>
 * @see <br>
 *      Common Problems - <a
 *      href="http://cwe.mitre.org/data/definitions/330.html">CWE-330: Use of
 *      Insufficiently Random Values</a>
 * @see <br>
 *      <a href="http://www.cs.berkeley.edu/~daw/rnd/" >Randomness for
 *      crypto</a>
 * @see <br>
 *      <a href="http://en.wikipedia.org/wiki/Randomness_extractor">Randomness
 *      Extractor</a>
 * 
 * @see <br>
 *      <a href="http://csrc.nist.gov/groups/ST/toolkit/index.html" >NIST -
 *      Cryptographic Toolkit</a>
 * @see <br>
 *      <a href="http://csrc.nist.gov/publications/PubsSPs.html" >NIST - Special
 *      Publications (800 Series)</a>
 * @see <br>
 *      <a href=
 *      "http://csrc.nist.gov/publications/nistpubs/800-90/SP800-90revised_March2007.pdf"
 *      >NIST Special Publication 800-90: Recommendation for Random Number
 *      Generation using Deterministic Random Bit Generators.</a>
 * @author <a href="mailto:Anton.Kabysh@gmail.com">Anton Kabysh</a> - Code
 * @author <br>
 *         NIST 800-90 autors (Elaine Barker, John Kelsey) - Specification
 * 
 */
public abstract class Cryptorandomness extends Randomness {
	/**
	 * The CSPRNG uses Hash_CSPRNG algorithm to generate pseudo-random number.
	 * Hash_CSPRNG algorithm is a standard recommended by National Institute of
	 * Secure Technology (NIST SP800-90), which uses cryptographic hash
	 * functions (SHA-256) to generate random numbers. The strength of CSPRNG
	 * not only depends on the generation algorithm, but also on the strength of
	 * entropy input. A key process in the generation of random numbers is
	 * entropy accumulation. During initialization of the CSPRNG, it is critical
	 * to accumulate entropy from the entropy sources. Entropy accumulation is
	 * the process by which a CSPRNG acquires a new unpredictable internal
	 * state. The entropies are collected into a hash-based pool using
	 * Kern::RandomSalt.
	 * 
	 * <p>
	 * The quality of the output of the CSPRNG can be improved by providing it
	 * with data known to be random. Such data is referred to as entropy data.
	 * Entropy data sources can either be:
	 */
	private static final int SHA1_KEY = 20; /* bytes */
	private static final int SHA256_KEY = 32;/* bytes */

	/**
	 * The intent of a <i>personalization string</i> is to differentiate this
	 * instantiation from all other instantiations that might ever be created.
	 * During instantiation, a personalization string should be used to derive
	 * the seed.
	 */
	protected transient final BigInteger personalizationString;

	/**
	 * Default constructor define optional <i>personalization string</i> of bits
	 * that provides personalization information. Personalization string is
	 * combined with a secret input and a nonce to produce a seed. The
	 * personalization string <b>should</b> be set to some unmodifiable
	 * bitstring that is as unique as possible, may include secret information.
	 * Secret information <b>should not</b> be used in the personalization
	 * string if it requires a level of protection that is greater than the
	 * intended <i>security strength</i> of the CSPRNG instantiation. Following
	 * NIST recommendations, good choices for the personalization string
	 * contents include:<br>
	 * <ol>
	 * <li>
	 * Device serial numbers,
	 * <li>
	 * Public keys,
	 * <li>
	 * Special secret key values for this specific instantiation,
	 * <li>
	 * Secret per-module or per-device values,
	 * <li>
	 * User identification,
	 * <li>
	 * Timestamps,
	 * <li>
	 * Network addresses,
	 * <li>
	 * Application identifiers,
	 * <li>
	 * Protocol version identifiers,
	 * <li>
	 * Random numbers,
	 * <li>
	 * Seedfiles,
	 * <li>
	 * Nonce.
	 * </ol>
	 * Or some combination of this.
	 * <p>
	 * 
	 * If personalization string is <code>null</code> or represented by empty
	 * array, then used underlying default algorithm to determine
	 * personalization string in according to <i>security strength</i> as
	 * combination of NIST recommendation techniques.
	 * <p>
	 * <b>See also at NIST SP 800-90:</b>
	 * <ul>
	 * <li>Section 8.7.1 - Personalization String, p 21.
	 * </ul>
	 * 
	 * @param personalizationString
	 *            - an optional input that provides personalization information.
	 *            Maximum personalization string length if configured by
	 *            {@link CSPRNG#MAX_PERSONALIZATION_STRING_LENGTH} with default
	 *            value 1024 bytes.
	 * @throws IllegalArgumentException
	 *             if <code>personalizationString</code> length is greater than
	 *             <i>max_personalization_string_length</i> value.
	 */
	protected Cryptorandomness(byte[] personalizationString) {

		if (personalizationString == null || personalizationString.length == 0)
			personalizationString = generatePerosnalizationString();

		final int maxLength = CSPRNG.MAX_PERSONALIZATION_STRING_LENGTH.get();

		if (personalizationString.length > maxLength)
			throw new IllegalArgumentException(
					"A personalization string length "
							+ personalizationString.length
							+ "greater than Maximum personalization string length ("
							+ maxLength + ")");

		// test personalization string for sufficient entropy.

		this.personalizationString = new BigInteger(personalizationString);

	}

	/**
	 * Returns a new <code>Cryptorandomness</code> object that implements the
	 * specified Cryptosecure Random Number Generator algorithm (
	 * {@linkplain CSPRNG}).
	 * 
	 * @param algorithm
	 *            a specified algorithm.
	 * 
	 * @return a new Cryptorandomness generator
	 */
	public static final Cryptorandomness from(CSPRNG algorithm) {
		return algorithm.newInstance();
	}

	/**
	 * <i>PROVISIONAL API, WORK IN PROGRESS:</i> Create {@link Cryptorandomness}
	 * from the specified SPI.
	 * 
	 * @param spi
	 * @return the SPRNG from specified SPI
	 */
	public static final Cryptorandomness from(SecureRandomSpi spi) {
		throw new UnsupportedOperationException();
	}

	// ///////////////////////////////////////////////////////////
	// ///////////////// ABSTRACT CSPRNG FUNCTIONS /////////////////
	// ///////////////////////////////////////////////////////////

	/**
	 * The <b>instantiate function</b> acquires entropy input and may combine it
	 * with a {@linkplain Cryptorandomness#nonce() nonce} and a
	 * {@linkplain Cryptorandomness#personalizationString personalization
	 * string} to create a seed from which the <i>initial internal state</i> is
	 * created.
	 * <p>
	 * A CSPRNG shall be instantiated prior to the
	 * {@linkplain Cryptorandomness#read(ByteBuffer) generation} of pseudorandom
	 * bits. The instantiate function:
	 * <ol>
	 * <li>Checks the validity of the input parameters,
	 * <li>Determines the {@linkplain Cryptorandomness#securityStrength()
	 * security strength} for the CSPRNG instantiation,
	 * <li>Determines any CSPRNG mechanism specific parameters (e.g., elliptic
	 * curve domain parameters),
	 * <li>Obtains {@linkplain Cryptorandomness#getEntropyInput(int, int, int)
	 * entropy input} with entropy sufficient to support the security strength,
	 * <li>Obtains the {@linkplain Cryptorandomness#nonce() nonce} (if
	 * required),
	 * <li>Determines the <i>initial internal state</i> using the instantiate
	 * algorithm,
	 * <li>Open instantiation to generate random bits.
	 * </ol>
	 * <p>
	 * The seed material used to determine a seed for instantiation consists of
	 * entropy input, a nonce and an optional personalization string. Depending
	 * on the CSPRNG mechanism and the source of the entropy input, a derivation
	 * function may be required to derive a seed from the seed material.
	 * However, in certain circumstances, the CSPRNG mechanism based on block
	 * cipher algorithms may be implemented without a derivation function.
	 * <p>
	 * Seed Construction for instantiation generated and handled as specified in
	 * NIST 800-90 recommendations. The hash-based derivation function used in
	 * default implementation to create cryptographic seed from specified
	 * entropy input, nonce, and personalization string. It hashes an input
	 * string and returns the requested number of bits.
	 * <p>
	 * <b>See also at NIST SP 800-90:</b>
	 * <ul>
	 * <li>Section 8.6.1 Seed Construction for Instantiation, p. 18
	 * <li>Section 8.6.7 Nonce, p. 19
	 * <li>Section 8.7.1 Personalization String, p. 21
	 * <li>Section 9.1 Instantiating a DRBG, p. 23
	 * <li>Section 10.1.1.2 Instantiation of Hash_DRBG, p. 36-37
	 * <li>Section 10.1.2.3 Instantiation of HMAC_DRBG, CSPRNG2
	 * <li>Section 10.4.1 Derivation Function Using a Hash Function (Hash_df),
	 * p. 64
	 * <li>Section Derivation Function Using a Block Cipher Algorithm
	 * (Block_Cipher_df), p. 65
	 * </ul>
	 */
	@Override
	public abstract void reset();

	/**
	 * The <b>generate function</b> is used to generate the requested
	 * pseudorandom bits after {@linkplain Cryptorandomness#reset()
	 * instantiation} or {@linkplain Cryptorandomness#reseed(ByteBuffer)
	 * reseeding} using the <i>generate algorithm</i>.
	 * <p>
	 * The generate function:
	 * <ol>
	 * <li>
	 * Checks the validity of the input parameters (
	 * {@linkplain Cryptorandomness#isOpen() is open}, is instantiated).
	 * <li>
	 * Calls the reseed function to obtain sufficient entropy if the
	 * instantiation needs additional entropy because the end of the seedlife
	 * has been reached or prediction resistance is required.
	 * <li>
	 * Generates the requested pseudorandom bits using the generate algorithm.
	 * <li>
	 * Updates the working state.
	 * <li>
	 * Returns the requested pseudorandom bits to the consuming application.
	 * </ol>
	 * <p>
	 * In other words, transfers a sequence generated bytes from this CSPRNG
	 * into the given buffer. An attempt is made to read up to <i>r</i> bytes
	 * from RBG, where <i>r</i> is the number of bytes <i>remaining</i> in the
	 * buffer, that is, <tt>buffer.remaining()</tt>, at the moment this method
	 * is invoked.
	 * <p>
	 * Suppose that a byte sequence of length <i>n</i> is read, where <tt>0</tt>
	 * &nbsp;<tt>&lt;=</tt>&nbsp;<i>n</i>&nbsp;<tt>&lt;=</tt>&nbsp;<i>r</i>.
	 * This byte sequence will be transferred into the buffer so that the first
	 * byte in the sequence is at index <i>p</i> and the last byte is at index
	 * <i>p</i>&nbsp;<tt>+</tt>&nbsp;<i>n</i>&nbsp;<tt>-</tt>&nbsp;<tt>1</tt>,
	 * where <i>p</i> is the buffer's position at the moment this method is
	 * invoked. Upon return the buffer's position will be equal to
	 * <i>p</i>&nbsp;<tt>+</tt>&nbsp;<i>n</i>; its limit will not have changed.
	 * A read operation might not fill the buffer, and in fact it might not read
	 * any bytes at all. Whether or not it does so depends upon the nature and
	 * state of the channel.
	 * <p>
	 * <p>
	 * This method may be invoked at any time. If another thread has already
	 * initiated a read operation upon this channel, however, then an invocation
	 * of this method will block until the first operation is complete (no
	 * interruption).
	 * <p>
	 * <b>See also at NIST SP 800-90:</b>
	 * <ul>
	 * <li>Section 9.3 Generating Pseudorandom Bits Using a DRBG, p. 28
	 * <li>Section 10.1.1.4 Generating Pseudorandom Bits Using Hash_DRBG, p. 38
	 * <li>Section 10.1.2.5 Generating Pseudorandom Bits Using HMAC_DRBG, p. 43
	 * <li>Appendix F: (Informative) Example Pseudocode for Each DRBG
	 * </ul>
	 * 
	 * @param buffer
	 *            The buffer into which random bytes are to be transferred
	 * 
	 * @return The number of bytes read, possibly zero.
	 * 
	 * @throws NullPointerException
	 *             if <code>buffer</code> is <code>null</code>.
	 * 
	 * @throws NonReadableChannelException
	 *             If this CSPRNG was not opened for reading (is
	 *             {@linkplain Cryptorandomness#close() closed}).
	 */

	@Override
	public abstract int read(ByteBuffer buffer);

	/**
	 * The <b>reseed function</b> acquires new entropy input and combines it
	 * with the <i>current internal state</i> and any additional input that is
	 * provided to create a new seed and a new internal state. The reseeding of
	 * an instantiation is not required, but is recommended whenever a comsuming
	 * application and implementation are able to perform this process.
	 * Reseeding will insert additional entropy into the generation of
	 * pseudorandom bits.
	 * <p>
	 * Reseeding may be:
	 * <ul>
	 * <li>
	 * explicitly requested by a consuming application,
	 * <li>
	 * performed when prediction resistance is requested by a consuming
	 * application,
	 * <li>
	 * triggered by the generate function when a predetermined number of
	 * pseudorandom outputs have been produced or a predetermined number of
	 * generate requests have been made (i.e., at the end of the seedlife), or
	 * <li>
	 * triggered by external events (e.g., whenever sufficient entropy is
	 * available).
	 * </ul>
	 * <p>
	 * The reseed function:
	 * <ol>
	 * <li>
	 * Checks the validity of the input parameters,
	 * <li>
	 * Obtains entropy input with sufficient entropy to support the security
	 * strength, and
	 * <li>
	 * Using the reseed algorithm, combines the current working state with the
	 * new entropy input and any additional input to determine the new working
	 * state.
	 * <li>
	 * Open instantiation to generate random bits.
	 * </ol>
	 * <p>
	 * The seed material for reseeding consists of a value that is carried in
	 * the internal state, new entropy input and, optionally, additional input.
	 * The internal state value and the entropy input are required. The entropy
	 * input <b>shall</b> have entropy that is equal to or greater than the
	 * security strength of the instantiation. Additional entropy may be
	 * provided in the nonce or the optional personalization string during
	 * instantiation, or in the additional input during reseeding and
	 * generation, but this is not required. A derivation function may be
	 * required for reseeding.
	 * 
	 * <p>
	 * <b>See also at NIST SP 800-90:</b>
	 * <ul>
	 * <li>Section 8.6.8 Reseeding, p. 20.
	 * <li>Section 9.2 Reseeding a DRBG Instantiation, p. 26
	 * <li>Section 10.1.1.3 Reseeding a Hash_DRBG Instantiation, p. 37
	 * <li>Section 10.1.2.4 Reseeding an HMAC_DRBG Instantiation, p. 43
	 * </ul>
	 * 
	 * @param additionalInput
	 *            an additional Input (Optional). An optional input. The maximum
	 *            length of the additional_input (
	 *            <code>max_additional_input_length</code>) is implementation
	 *            dependent, but shall be less than or equal to the maximum
	 *            value specified for the given CSPRNG mechanism. Suppose that
	 *            <code>max_additional_input_length</code> <b>shall not</b> be
	 *            greater than {@link CSPRNG#MAX_ENTROPY_INPUT_LENGTH
	 *            max_entropy_input_length}. If the input by a consuming
	 *            application of additional_input is not supported, then
	 *            additional entropy may be provided in the nonce or the
	 *            optional personalization string during instantiation, but this
	 *            is not required.
	 * 
	 * 
	 * @throws IllegalArgumentException
	 *             if <code>additionalInput</code> length is greater than
	 *             <i>max_additional_input_length</i> value.
	 */
	public abstract void reseed(ByteBuffer additionalInput);

	/**
	 * The <b>uninstantiate function</b> zeroizes (i.e., erases) the internal
	 * state. The internal state for an instantiation may need to be “released”
	 * by erasing (i.e., zeroizing) the contents of the internal state.
	 * <p>
	 * The uninstantiate function:
	 * <ol>
	 * <li>
	 * Closes this instantiation to ever produce random bytes. <br>
	 * <li>
	 * Erases the internal state to <code>null</code> value.
	 * </ol>
	 * <p>
	 * The instantiation may be instantiated again calling one of
	 * {@linkplain Cryptorandomness#reset() reset()} or
	 * {@linkplain Cryptorandomness#reseed(ByteBuffer) reseed()} methods.
	 * <p>
	 * <b>See also at NIST SP 800-90:</b>
	 * <ul>
	 * <li>Section 9.4 Removing a DRBG Instantiation, p. 32
	 * </ul>
	 */
	@Override
	public abstract void close();

	/**
	 * Returns the <i>seed length</i> used by underlying CSPRNG algorithm in
	 * bytes. The minimum <i>seed length</i> depends on the CSPRNG mechanism and
	 * the <i>security strength</i> required by the consuming application.
	 * 
	 * @return the <i>seed length</i> of this CSPRNG in bytes
	 */
	protected abstract int seedlen();

	/**
	 * <i>PROVISIONAL API, WORK IN PROGRESS:</i> Returns limit of bytes
	 * generated between two autoreseedings.
	 * 
	 * @return current limit
	 */
	public long limit() {
		return 0;
	}

	/**
	 * <i>PROVISIONAL API, WORK IN PROGRESS:</i> Set's new limit of bytes
	 * 
	 * @param newLimit
	 * @return this
	 */
	public Cryptorandomness limit(long newLimit) {
		throw new UnsupportedOperationException();
	}

	/**
	 * <i>PROVISIONAL API, WORK IN PROGRESS:</i>Try to reseed on every call with
	 * specified probability.
	 * 
	 * @return this
	 */
	public Cryptorandomness reseed(float probability) {
		throw new UnsupportedOperationException();

	}

	/**
	 * <i>PROVISIONAL API, WORK IN PROGRESS:</i> Escape from attacker
	 * (asynchronous call).
	 * 
	 * @return this
	 */
	public Cryptorandomness escape() {
		throw new UnsupportedOperationException();
	}

	/**
	 * Returns the <i>security strength</i> of this CSPRNG in bytes. <i>Security
	 * strength</i> - is a number associated with the amount of work (that is,
	 * the number of operations) that is required to break a cryptographic
	 * algorithm or system. The amount of work needed is
	 * 2<sup>security_strength</sup>. From this value depends size of
	 * {@linkplain Cryptorandomness#nonce() nonce} string and used derivation
	 * function.
	 * <p>
	 * A security strength for the instantiation is requested by a consuming
	 * application during instantiation, and the instantiate function obtains
	 * the appropriate amount of entropy for the requested security strength.
	 * The actual security strength supported by a given instantiation depends
	 * on the CSPRNG implementation and on the amount of entropy provided to the
	 * instantiate function. Note that the security strength actually supported
	 * by a particular instantiation could be less than the maximum security
	 * strength possible for that CSPRNG implementation . For example, a CSPRNG
	 * that is designed to support a maximum security strength of 256 bits
	 * could, instead, be instantiated to support only a 128-bit security
	 * strength if the additional security provided by the 256-bit security
	 * strength is not required (i.e., by requesting only 128 bits of entropy
	 * during instantiation, rather than 256 bits of entropy).
	 * <p>
	 * It is hard to determine security strength for all kind of CSPRNG so, we
	 * use lower bound of security strength defined as seedlen/2 Recommendation
	 * taken from SP 800 57, Table 3, p. 64 Hash function security strengths for
	 * cryptographic applications:
	 * <p>
	 * The default CSPRNG using following rules:
	 * <p>
	 * If <i>security strength</i> <= <code>128</code> than used <b>SHA-1</b>
	 * hash function as <i>derivation function</i>.<br>
	 * Else if <i>security strength</i> <= <code>256</code> than used
	 * <code>SHA-256</code> hash function as <i>derivation function</i>.<br>
	 * If <i>security strength</i> > <code>256</code> used <code>SHA-512</code>
	 * hash function as <i>derivation function</i>.<br>
	 * If <code>SHA</code> hash functions family is not supported, used bundled
	 * <code>MD5</code> hash function as as <i>derivation function</i>.
	 * <p>
	 * <b>See also at NIST SP 800-57:</b>
	 * <ul>
	 * <li>Section 5.6.1 Comparable Algorithm Strengths, p. 61
	 * </ul>
	 * <p>
	 * <b>See also at NIST SP 800-90:</b>
	 * <ul>
	 * <li>Section 8.4 Security Strengths Supported by an Instantiation, p 15.
	 * </ul>
	 * 
	 * @return the <i>security strength</i> of this CSPRNG in bytes
	 */
	protected int securityStrength() {
		// It is hard to determine security strength for all kind of CSPRNG
		// so, we use lower bound of security strength defined as seedlen/2
		// Recommendation taken from SP 800 57, Table 3, p. 64
		// Hash function security strengths for cryptographic applications,
		return seedlen() / 2;
	}

	/**
	 * A <b>entropy function</b> is used to obtain entropy input. The function
	 * call is requests a string of bits (<i>entropy_input</i>) with at least
	 * <i>min_entropy</i> bytes of entropy from <i>source of entropy</i> to
	 * provide desired <i>security strength</i>. The length for the string shall
	 * be equal to or greater than <i>min_length</i> bits, and less than or
	 * equal to <i>max_length</i> bits. The
	 * 
	 * <code> security_strength  {@literal <=} min_entropy  {@literal <=} min_length {@literal <=}  seedlen {@literal <=} max_length 
	 * </code> <b>shall</b> be required.
	 * 
	 * <p>
	 * The source of the entropy input shall be either:
	 * <ol>
	 * <li>
	 * An Approved non-deterministic random bit generators ( {@linkplain TRNG
	 * True Random Number Generators}).
	 * <li>
	 * An Approved CSPRNG, thus forming a chain of at least two CSPRNGs; the
	 * highestlevel CSPRNG in the chain shall be seeded by an Approved NRBG or
	 * an entropy source.
	 * <li>
	 * An appropriate entropy source.
	 * </ol>
	 * <p>
	 * The entropy input <b>shall not</b> be provided by a consuming application
	 * as an input parameter in an instantiate or reseed request.
	 * <p>
	 * The most important feature of the interaction between the entropy input
	 * and the CSPRNG mechanism is that if an adversary does not know the
	 * entropy input, then he can’t tell the difference between the pseudorandom
	 * bits and a stream of truly random bits, let alone predict any of the
	 * pseudorandom bits. On the other hand, if he knows (or can guess) the
	 * entropy input, then he will be able to predict or reproduce the
	 * pseudorandom bits. Thus, the security of the CSPRNG output is directly
	 * related to the adversary’s inability to guess the entropy input and the
	 * seed. The entropy source is the critical component of an RBG that
	 * provides un-guessable values for the deterministic algorithm to use as
	 * entropy input for the random bit generation process.
	 * <p>
	 * Note that an implementation may choose to define this functionality
	 * differently. The developer using a own source shall document the
	 * adversary’s ability to predict or observe the output of the noise source
	 * and shall provide a model that justifies his claims for the amount of
	 * entropy produced by the noise source (i.e., how unguessable the values
	 * are for the observer).
	 * <p>
	 * <b>See also at NIST SP 800-90:</b>
	 * <ul>
	 * <li>Appendix C: (Normative) Entropy and Entropy Sources.
	 * </ul>
	 * 
	 * @param min_entropy
	 *            number bits of entropy (required minimum entropy for
	 *            instantiate and reseed - <i>security strength</i>).
	 * @param min_length
	 *            minimum length of returned bitstring.
	 * @param max_length
	 *            maximum length of returned bitstring. The <i>max_length</i>
	 *            shall not be greater than value configured by
	 *            {@linkplain CSPRNG#MAX_ENTROPY_INPUT_LENGTH Maximum entropy
	 *            input length} (default 1024 bytes).
	 * 
	 * @return string of bits with at least <i>min_entropy</i> bits of entropy.
	 * 
	 * @throws IllegalArgumentException
	 *             <ol>
	 *             <li>if <code> min_entropy</code> is negative, <li>if <code>
	 *             min_entropy</code> is lower than <i>security strength</i>
	 *             (Optional), <li>if <code>min_length</code> is lower than
	 *             <code> min_entropy</code>, <li>if <code>min_length</code> is
	 *             lower than <code>seedlen</code> (Optional),<li>if <code>
	 *             min_length</code> is greater than <code>max_length</code>,
	 *             <li>if <code> max_length </code> is greater than <i>Maximum
	 *             entropy input length</i> value.
	 *             </ol>
	 * @throws InternalError
	 *             if no such entropy in the system.
	 * 
	 */
	protected byte[] getEntropyInput(int min_entropy, int min_length,
			int max_length) {
		if (min_entropy < 0)
			throw new IllegalArgumentException(ENTROPY_INPUT_ERRORS[0]);
		if (min_entropy < securityStrength())
			throw new IllegalArgumentException(ENTROPY_INPUT_ERRORS[1]);
		if (min_length < min_entropy)
			throw new IllegalArgumentException(ENTROPY_INPUT_ERRORS[2]);
		if (min_length < seedlen())
			throw new IllegalArgumentException(ENTROPY_INPUT_ERRORS[3]);
		if (min_length > max_length)
			throw new IllegalArgumentException(ENTROPY_INPUT_ERRORS[4]);
		if (max_length > CSPRNG.MAX_ENTROPY_INPUT_LENGTH.get())
			throw new IllegalArgumentException(ENTROPY_INPUT_ERRORS[5]);

		// generate entropy from native source, shall be cryptosecure
		byte[] entropy = new byte[min_length = min_entropy];
		Truerandomness.shared(TRNG.NATIVE).read(entropy);
		return entropy;
	}

	static final String[] ENTROPY_INPUT_ERRORS = {
			"The min_entropy is negative",
			"The min_entropy is lower than desired security_strength",
			"The min_length of entrpy input is lower than min_entropy",
			"The min_length is lower than seedlen. Cryptographic seed can'not be created!",
			"The min_length is greater than max_length.",
			"The max_length is greater than MAX_ENTROPY_INPUT_LENGTH" };

	/**
	 * A <b>limited entropy function</b> is used to obtain entropy input. Equal
	 * to full <b>entropy function</b> function from NIST 800-90 recomendations,
	 * where <i>min_length</i> is equal to <i>min_entropy</i>, and
	 * <i>max_length</i> is equal to
	 * {@linkplain CSPRNG#MAX_ENTROPY_INPUT_LENGTH Maximum entropy input length}
	 * (default 1024 byte). <h3>Common Problems</h3>
	 * <ul>
	 * <li><b><a href="http://cwe.mitre.org/data/definitions/336.html">CWE-336:
	 * Same Seed in PRNG</a></b> - A PRNG uses the same seed each time the
	 * product is initialized. If an attacker can guess (or knows) the seed,
	 * then he/she may be able to determine the "random" number produced from
	 * the PRNG. <b>Solution</b>: Do not reuse PRNG seeds. Consider a PRNG that
	 * periodically re-seeds itself as needed from a high quality pseudo-random
	 * output, such as hardware devices.
	 * <li><b><a href="http://cwe.mitre.org/data/definitions/337.html">CWE-337:
	 * Predictable Seed in PRNG</a></b> - A PRNG is initialized from a
	 * predictable seed, e.g. using process ID or system time. <b>Solution</b>:
	 * Consider a PRNG which re-seeds itself, as needed from a high quality
	 * pseudo-random output, like hardware devices.
	 * <li><b><a href="http://cwe.mitre.org/data/definitions/339.html">CWE-339:
	 * Small Seed Space in PRNG</a></b> - A PRNG uses a relatively small space
	 * of seeds. <b>Solution</b>: Use well vetted pseudo-random number
	 * generating algorithms with adequate length seeds. Pseudo-random number
	 * generators can produce predictable numbers if the generator is known and
	 * the seed can be guessed. A 256-bit seed is a good starting point for
	 * producing a "random enough" number.
	 * </ul>
	 * <h4>Reccomendation:</h4>
	 * <ul>
	 * <li>Use products or modules that conform to FIPS 140-2 to avoid obvious
	 * entropy problems. Consult FIPS 140-2 Annex C
	 * ("Approved Random Number Generators").
	 * <li>
	 * Consider a PRNG which re-seeds itself, as needed from a high quality
	 * pseudo-random output, like hardware devices.
	 * </ul>
	 * 
	 * @param min_entropy
	 *            number bytes of entropy.
	 * @return a byte array containing <i>min_entropy</i> bytes of entropy.
	 */
	protected final byte[] getEntropyInput(int min_entropy) {
		return getEntropyInput(min_entropy, min_entropy,
				CSPRNG.MAX_ENTROPY_INPUT_LENGTH.get());
	}

	/**
	 * <i>Nonce</i> - is a time-varying value that has at most a negligible
	 * chance of repeating, e.g., a random value that is generated anew for each
	 * use, a timestamp, a sequence number, or some combination of these. A
	 * nonce required in the construction of a seed during instantation in order
	 * to provide a security cushion to block certain attacks.
	 * <p>
	 * The nonce shall be either:<br>
	 * <ul>
	 * a. An unpredictable value with at least (1/2 <i>
	 * {@linkplain Cryptorandomness#securityStrength() security_strength} </i>)
	 * bytes of entropy,<br>
	 * b. A value that is expected to repeat no more often than a (1/2
	 * <i>security_strength</i>)-byte random string would be expected to repeat.
	 * </ul>
	 * For case a, the nonce may be acquired from the same source and at the
	 * same time as the <i>entropy input</i> . In this case, the seed could be
	 * considered to be constructed from an “extra strong” entropy input and the
	 * optional {@linkplain Cryptorandomness#personalizationString
	 * personalization string}, where the entropy for the entropy input is equal
	 * to or greater than (3/2 <i>security_strength</i>) bytes.
	 * <p>
	 * This implementation reads 1/2 <i>security_strength</i>)-bytes of entropy
	 * from <b>entropy function</b>.
	 * <p>
	 * The default <code>Cryptorandomness</code> implementation use a combined
	 * non-linear approach: a (1/2 <i>security_strength</i>)-byte random value
	 * initialized by system entropy, entropy function and internal cryptosecure
	 * RNG. In resutl, <i>Nonce</i> is a non-linear function of
	 * <code>nonce</code> bitstring, counter and cryptosecure RNG.
	 * <p>
	 * 
	 * @see <a href="http://en.wikipedia.org/wiki/Cryptographic_nonce">
	 *      Wikipedia - Cryptographic nonce</a>
	 * @return nonce bytes
	 */
	protected byte[] nonce() {
		final int nonceEntropy = Math.round((float) (securityStrength() * 0.5));
		return getEntropyInput(nonceEntropy);
	}

	/**
	 * Two different instances of <code>Cryptorandomness</code> are never equal
	 * to each other (consistent with {@linkplain Cryptorandomness#hashCode()
	 * hashCode}). CSPRNG must hide their internal states to prevent possible
	 * attacks.
	 * 
	 * @param obj
	 *            the reference object with which to compare.
	 * @return true if <code>this == obj</code>; false otherwise.
	 */
	@Override
	public final boolean equals(Object obj) {
		return super.equals(obj);
	}

	/**
	 * Returns the <i>unique</i> hash code value of this
	 * <code>Cryptorandomness</code> (consistent with
	 * {@linkplain Cryptorandomness#equals(Object) equals}).
	 * <p>
	 * Unique hash code value used to hide internal state of
	 * <code>Cryptorandomness</code> and prevent some possible attacks, where
	 * internal state of object can be restored using hash code value.
	 * 
	 * @return a <i>unique</i> hash code value for this object.
	 */
	@Override
	public final int hashCode() {
		return super.hashCode();
	}

	/**
	 * <i>TODO PROVISIONAL API, WORK IN PROGRESS:</i> Returns a random string of
	 * hex characters from a secure random sequence.
	 * 
	 * @param length
	 *            the length of the generated string
	 * @return the random string
	 * 
	 * @throws IllegalArgumentException
	 *             if <code>len <= 0</code>
	 */
	public String nextHexString(int length) {
		if (length <= 0) {
			throw new IllegalArgumentException("length must be positive: "
					+ length);
		}

		// Get SecureRandom and setup Digest provider
		MessageDigest alg = null;
		try {
			alg = MessageDigest.getInstance("SHA-1");
		} catch (NoSuchAlgorithmException ex) {
			// this should never happen
			throw (InternalError) new InternalError().initCause(ex);
		}
		alg.reset();

		// Compute number of iterations required (40 bytes each)
		int numIter = (length / 40) + 1;

		StringBuffer outBuffer = new StringBuffer();
		for (int iter = 1; iter < numIter + 1; iter++) {
			byte[] randomBytes = new byte[40];
			read(randomBytes);
			alg.update(randomBytes);

			// Compute hash -- will create 20-byte binary hash
			byte hash[] = alg.digest();

			// Loop over the hash, converting each byte to 2 hex digits
			for (int i = 0; i < hash.length; i++) {
				Integer c = Integer.valueOf(hash[i]);

				/*
				 * Add 128 to byte value to make interval 0-255 This guarantees
				 * <= 2 hex digits from toHexString() toHexString would
				 * otherwise add 2^32 to negative arguments
				 */
				String hex = Integer.toHexString(c.intValue() + 128);

				// Keep strings uniform length -- guarantees 40 bytes
				if (hex.length() == 1) {
					hex = "0" + hex;
				}
				outBuffer.append(hex);
			}
		}
		return outBuffer.toString().substring(0, length);
	};

	// /**
	// * Cryptosecure generator can't be cloned, so it throws
	// * <code>CloneNotSupportedException</code>.
	// */
	// @Override
	// protected final Cryptorandomness clone() throws
	// CloneNotSupportedException {
	// throw new CloneNotSupportedException();
	// }

	// //////////////////////////////////////////////////////////
	// //////////////// PRIVATE MECHANISMS //////////////////////
	// //////////////////////////////////////////////////////////
	/**
	 * The intent of a personalization string is to differentiate
	 * <code>this</code> instantiation from all other instantiations that might
	 * ever be created. The personalization string <b>should</b> be set to some
	 * unmodifiable bitstring that is as unique as possible, may include secret
	 * information, and <b>should</b> be specified into
	 * {@linkplain Cryptorandomness#Cryptorandomness(Truerandomness, byte[])
	 * constructor}.
	 * <p>
	 * During instantiation, a personalization string should be used to derive
	 * the seed. Following NIST recommendations, good choices for the
	 * personalization string contents include:<br>
	 * <ul>
	 * 1. Public keys<br>
	 * 2. Special secret key values for this specific instantiation<br>
	 * 3. User identification<br>
	 * 4. Timestamps<br>
	 * 5. Network addresses<br>
	 * 6. Application identifiers<br>
	 * 7. Random numbers<br>
	 * 8. Nonce<br>
	 * </ul>
	 * Current personalization string creation algorithm collect data from
	 * various sources and hash it together using cryptosecure hash function.
	 */
	// Paranoic personalization string
	private static final byte[] generatePerosnalizationString() {

		SecureRandom random;
		try { // get SecureRandom instance.
			random = SecureRandom.getInstance("SHA1PRNG", "SUN");
		} catch (Exception e) {
			// Constructs a secure random number generator (RNG) implementing
			// the default random number algorithm.
			random = new SecureRandom();
		}

		MessageDigest md;
		try {
			md = MessageDigest.getInstance("SHA1");
		} catch (NoSuchAlgorithmException e) {
			md = null; // TODO
		}

		try { // create Public/Private Key pair.
			/* Generate a key pair */
			// 1. Public keys
			KeyPairGenerator keyGen = KeyPairGenerator
					.getInstance("DSA", "SUN");

			keyGen.initialize(1024/* bits */, random);
			KeyPair pair = keyGen.generateKeyPair();

			// Special secret key values for this specific instantiation
			md.update(pair.getPrivate().getEncoded());
		} catch (Exception e) {
			md.update((byte) e.hashCode());
		}

		// User identification
		String[] iserinfo = { "user.name", "user.country", "user.dir" };

		for (String prop : iserinfo) {
			String data = System.getProperty(prop);
			if (data != null)
				md.update(data.getBytes());
		}

		// Time stamps
		md.update((byte) System.nanoTime());

		// Network addresses
		try {
			InetAddress address = InetAddress.getLocalHost();
			md.update(address.getAddress());
		} catch (UnknownHostException e) {
			md.update((byte) e.hashCode());
		}

		// Application identifiers
		md.update(TRNG.getSystemEntropy());

		return md.digest();
	}

	/**
	 * The maximum security strength that can be supported by each CSPRNG based
	 * on a hash function is the security strength of the hash function used;
	 * the security strengths for the hash functions when used for random number
	 * generation are provided in SP 800-57.
	 * <p>
	 * The hash function to be used <b>shall</b> meet or exceed the desired
	 * security strength of the consuming application.
	 * 
	 * @return used SHA version is one of {SHA, SHA-256, SHA-512}
	 */
	static final String defineSecureHashAlgorithm(final int security_strength) {
		if (security_strength <= SHA1_KEY)
			return "SHA";
		if (security_strength <= SHA256_KEY)
			return "SHA-256";
		else
			// SHA256_KEY_BYTES <= size, use SHA-512
			return "SHA-512";
	}

	// //////////////////////////////////////////////////////////
	// //////////////// SERVICE METHODS /////////////////////////
	// //////////////////////////////////////////////////////////
	/**
	 * Represents this CSPRNG as a <code>java.security.SecureRandom</code>.
	 * <p>
	 * This method convert this PRNG into {@link SecureRandom
	 * java.security.SecureRandom} instance, to be used instead it in java
	 * legacy code.
	 * <p>
	 * The view is typically part of the CSPRNG itself (created only once) and
	 * every call return this instance.
	 * 
	 * @return view as <code>java.security.SecureRandom</code> over this
	 *         Cryptorandomness.
	 */
	@Override
	public SecureRandom asRandom() {
		return this instanceof SecureCryptorandomness ? //
		((SecureCryptorandomness) this).random // SHA-1
				: new AsSecureRandom();
	}

	/**
	 * View as <code>java.util.Random</code> over Pseudorandomness.
	 * 
	 * @author Anton Kabysh
	 * 
	 */
	private final class AsSecureRandom extends java.security.SecureRandom {

		/**
		 * serial
		 */
		private static final long serialVersionUID = 4756758871717944514L;

		@Override
		public final boolean nextBoolean() {
			return Cryptorandomness.this.nextBoolean();
		}

		@Override
		public final void nextBytes(byte[] bytes) {
			Cryptorandomness.this.read(bytes);
		}

		@Override
		public double nextDouble() {
			return Cryptorandomness.this.nextDouble();
		}

		@Override
		public float nextFloat() {
			return Cryptorandomness.this.nextFloat();
		}

		@Override
		public int nextInt() {
			return Cryptorandomness.this.nextInt();
		}

		@Override
		public long nextLong() {
			return Cryptorandomness.this.nextLong();
		}

		@Override
		public synchronized void setSeed(long seed) {
			// no effect.
		}

		@Override
		public final String toString() {
			return Cryptorandomness.this.toString();
		}

		@Override
		public byte[] generateSeed(int numBytes) {
			return getEntropyInput(numBytes);
		}

		@Override
		public String getAlgorithm() {
			return toString();
		}

		@Override
		public synchronized void setSeed(byte[] seed) {
			reseed(ByteBuffer.wrap(seed));
		}
	}

}
