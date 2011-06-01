package org.randomness;

import java.nio.ByteBuffer;
import java.nio.channels.NonReadableChannelException;
import java.util.ConcurrentModificationException;

/**
 * This class specifies <i>True Random Number Generator</i> (TRNG) techniques
 * for the reading high quality, unpredictable random bytes from the specified
 * <i>entropy source</i>.
 * <p>
 * The best way to obtain truly random bits would be to observe a atomic or
 * subatomic physical phenomenon which is believed to exhibit random behavior.
 * Possible sources of entropy include {@linkplain TRNG#HOTBITS radioactive
 * decay}, thermal noise, shot noise, avalanche noise in Zener diodes, clock
 * drift, the timing of actual movements of a hard disk read/write head, and
 * {@linkplain TRNG#ATMSFERIC_NOISE radio noise}. Also, some computational
 * things can be used, such a {@linkplain TRNG#THREADS_SYNCHRONIZATION thread
 * synchronization}. However, physical phenomena and tools used to measure them
 * generally feature asymmetries and systematic biases that make their outcomes
 * not uniformly random. A randomness extractor, such as a {@linkplain CSPRNG
 * cryptographic hash function}, can be used to obtain uniformly distributed
 * bits from a non-uniformly random source, though at a lower bit rate.
 * <p>
 * TRNG is suitable to use in cryptography. Problems of TRNG is that they
 * usually not fast enough. Some applications need to generate millions of
 * random numbers as quickly as possible. For this purposes
 * {@linkplain Pseudorandomness Pseudorandom Number Generators} or
 * {@linkplain Cryptorandomness Cryptographically Secure Pseudorandom Number
 * Generators} can be used.
 * <h3>TRNG mechanisms</h3>
 * This specification based on strongly limited version of NIST 800-90 adopted
 * to describe mechanisms of True Random Number Generators (<i>see Appendix
 * C:(Normative) Entropy and Entropy Sources</i>).
 * <p>
 * The TRNG mechanisms class have four separate functions to handle the TRNG’s
 * <i>internal state</i>:
 * <ol>
 * <li>The {@linkplain Truerandomness#reset() instantiate function} determines
 * the <i>initial internal state</i> of TRNG and open it for reading random
 * bytes from <i>entropy source</i>. A TRNG <b>shall be</b>
 * {@linkplain Truerandomness#isOpen() opened} prior to the reading of random
 * bits. Opposite to {@linkplain Truerandomness#close() uninstantiate} function.
 * <li>The {@linkplain Truerandomness#read(ByteBuffer) generate function}
 * harvest random bits from entropy source per request, can determine entropy of
 * requested bits (optional, if possible) and reduce to independent bits if
 * requested bits has low quality entropy. RBG <b>should be</b>
 * {@linkplain Truerandomness#reset() instantiateed} before generation.
 * <li>The {@linkplain Truerandomness#close() uninstantiate function} close
 * (i.e., erases) this TRNG. Opposite to {@linkplain Truerandomness#reset()
 * instantiate} function.
 * <li>The health {@linkplain Truerandomness#test() test function} shall be
 * performed to determine that the TRNG mechanism is continuing to perform
 * correctly.
 * </ol>
 * <p>
 * <h3>TRNG Properties</h3>
 * <ul>
 * <li>Every entropy source <b>shall</b> include some source of unpredictable
 * data, which is referred to as a <i>noise source</i>.
 * <li>Before an entropy source is selected for providing entropy input to a, a
 * thorough evaluation of the amount of entropy it is capable of providing
 * <b>shall be</b> performed. An assessment <b>shall be</b> made of the amount
 * of entropy that has been obtained.
 * <li>The developer using a noise source <b>shall</b> document the adversary’s
 * ability to predict or observe the output of the noise source and shall
 * provide a model that justifies his claims for the amount of entropy produced
 * by the noise source (i.e., how unguessable the values are for the observer).
 * </ul>
 * <h3>TRNG Entropy source</h3>
 * Entropy is obtained from an entropy source. The entropy input required to
 * seed or reseed a PRNG <b>shall</b> be obtained either directly or indirectly
 * from an entropy source
 * <p>
 * <i>Entropy source</i> - a source of unpredictable data. There is no
 * assumption that the unpredictable data has a uniform distribution. The
 * entropy source includes a <i>noise source</i>, such as thermal noise or hard
 * drive seek times; a digitization process; an assessment process; an optional
 * conditioning process and health tests.
 * <p>
 * <i>Conditioned Entropy Source</i> - An entropy source that either includes a
 * conditioning function or for which conditioning is performed on the output of
 * the entropy source. The conditioning function ensures that the conditioned
 * entropy source provides full entropy bitstrings, i.e. the entropy of the
 * bitstring will be the same as its length. Health tests <b>shall be</b>
 * performed to determine that the entropy source is continuing to perform
 * correctly. <br>
 * <h3 align="center"><i>PROVISIONAL API, WORK IN PROGRESS</i></h3>
 * <p>
 * <h3>TODO:</h3>
 * <ol>
 * <li>Interruptible generation
 * <li>Support of selectable, nonblocking and asynchronous reading
 * <li>Randomness extraction
 * <li>Login\password instantiation
 * <li>Entropy pools
 * <li>Testing truerandomness (testing buffer)
 * <li>Whitening strategies (John von Neumann and others)
 * <li>Estimating entropy (Entropy, Chi-square Test, Arithmetic Mean, Monte
 * Carlo Value for Pi, Serial Correlation Coefficient)
 * <li>Hardware random number generators should be constantly monitored for
 * proper operation. RFC 4086 and FIPS Pub 140-2 include tests which can be used
 * for this.
 * </ol>
 * 
 * @see <a
 *      href="http://en.wikipedia.org/wiki/Hardware_random_number_generator">Wikipedia
 *      - Hardware random number generator</a>
 * @see <br>
 *      <a href="http://en.wikipedia.org/wiki/Randomness_extractor">Randomness
 *      Extractor</a>
 * @see <br>
 *      <a href=
 *      "http://stackoverflow.com/questions/3436376/what-is-the-most-secure-seed-for-random-number-generation?tab=votes#tab-top"
 *      >Stackoverflow - What is the most secure seed for random number
 *      generation?</a>
 * @see <br>
 *      <a href=
 *      "http://www.cecm.sfu.ca/~monaganm/teaching/CryptographyF08/random-bits.pdf"
 *      >About random bits (pdf)</a>
 * @author <a href="mailto:Anton.Kabysh@gmail.com">Anton Kabysh</a> - Code
 * @author <br>
 *         NIST 800-90 autors (Elaine Barker, John Kelsey) - Specification
 */
public abstract class Truerandomness extends Randomness {

	/**
	 * Default constructor.
	 */
	protected Truerandomness() {
	}

	// ///////////////////////////////////////////////////////////
	// ///////////////// ABSTRACT RBG FUNCTIONS //////////////////
	// ///////////////////////////////////////////////////////////

	/**
	 * The <b>instantiate function</b> determines the <i>initial internal
	 * state</i> of TRNG using the instantiate algorithm (possibly opens the
	 * entropy source). A TRNG shall be instantiated prior to the reading of
	 * random bits.
	 * <p>
	 * Opposite to {@linkplain Truerandomness#close() uninstantiate} function.
	 */
	@Override
	public abstract void reset();

	/**
	 * <i>TODO PROVISIONAL API, WORK IN PROGRESS:</i> Instantiate with specified
	 * login and password (for services with autorization such as
	 * {@link TRNG#RANDOM_ORG random.org} and {@link TRNG#QRBG QRBG} ).
	 * 
	 * @param login
	 * @param password
	 */
	public void reset(String login, String password) {
		throw new UnsupportedOperationException();
	}

	/**
	 * The <b>generate function</b> harvest random bits from entropy source per
	 * request, can determine entropy of requested bits (optional) and reduce to
	 * independent bits if requested bits has low quality entropy. In other
	 * words, reads a sequence harvested bytes from underlying entropy source
	 * into the given buffer. An attempt is made to read up to <i>r</i> bytes
	 * from TRNG, where <i>r</i> is the number of bytes <i>remaining</i> in the
	 * buffer, that is, <tt>buffer.remaining()</tt>, at the moment this method
	 * is invoked.
	 * <p>
	 * The process to obtain true-random bits from entropy source typically
	 * involves the following steps:
	 * <ol>
	 * <li><b>Harvest bits</b> - One first gathers some bits unknown to and
	 * unguessable by the adversary. These must come from some entropy source
	 * which is referred to a <i>noise source</i>.
	 * <li><b>Determine entropy(optional)</b> - The word “entropy” is used to
	 * describe a measure of randomness, i.e., a description of how hard a value
	 * is to guess. The second step is then to determine how many unguessable
	 * bits were thus harvested. Some entropy source are better than others in
	 * unguessability. But usually it is really hard to measure entropy of
	 * random input, so the better strategy to mix different entropy sources
	 * using hash mixing function.
	 * <li><b>Reduce to independent bits (optional)</b> - As a third step, one
	 * can compute a hash of the harvested bits to reduce them to independent,
	 * random bits. The hash function for this stage of operation needs to have
	 * each output bit functionally dependent on all input bits and functionally
	 * independent of all other output bits. Barring formal analysis, we assume
	 * that the hash functions which are claimed to be cryptographically strong
	 * (MD5 and SHA) have this characteristic.
	 * </ol>
	 * 
	 * @param buffer
	 *            The buffer into which entropy are to be transferred.
	 * 
	 * @return The number of bytes read from TRNG, possibly zero, or <tt>-1</tt>
	 *         if the TRNG has reached end-of-stream.
	 * 
	 * @throws NullPointerException
	 *             if <code>buffer</code> is <code>null</code>.
	 * 
	 * @throws NonReadableChannelException
	 *             If this TRNG was not opened for reading (is
	 *             {@linkplain Truerandomness#close() closed}).
	 * 
	 */
	@Override
	public abstract int read(ByteBuffer buffer);

	/**
	 * <i>TODO PROVISIONAL API, WORK IN PROGRESS:</i> Reads a sequence of bytes
	 * from specified entropy source and the conditioning function ensures that
	 * the conditioned entropy source provides entropy bitstrings, with
	 * specified <i>min_entropy</i>.
	 * <p>
	 * Entropy tests <b>shall be</b> performed to determine that the entropy
	 * source is continuing to perform correctly.
	 * 
	 * @param buffer
	 * @param min_entropy
	 *            number bytes of entropy.
	 * @return <code>true</code> if returned transfered bytes contains enough
	 *         entropy, <code>false</code> otherwise.
	 */
	public boolean readConditionally(ByteBuffer buffer, int min_entropy) {
		throw new UnsupportedOperationException();
	}

	/**
	 * <i>TODO PROVISIONAL API, WORK IN PROGRESS:</i> Reads a sequence of bytes
	 * from specified entropy source returning the amount of actual entropy
	 * obtained from an entropy source.
	 * <p>
	 * <i>See Appendix C:(Normative) Entropy and Entropy Sources</i>. C.3
	 * Entropy Assessment
	 * 
	 * @param buffer
	 * @return the entropy measurement that is known as <i>min-entropy</i>
	 *         (<i>H<sub>min</sub></i>).
	 */
	public double readAssessment(ByteBuffer buffer) {
		throw new UnsupportedOperationException();
	}

	/**
	 * The <b>uninstantiate function</b> zeroizes (i.e., erases) the internal
	 * state of TRNG (possibly close the entropy source).
	 * <p>
	 * Opposite to {@linkplain Truerandomness#reset() instantiate} function.
	 * <p>
	 * After a TRNG is closed, any further attempt to invoke
	 * {@linkplain Truerandomness#read(ByteBuffer) read} operations upon it will
	 * cause a <code>NonReadableChannelException</code> to be thrown.
	 * <p>
	 * If this TRNG is already closed then invoking this method has no effect.
	 * 
	 * This method may be invoked at any time. If some other thread has already
	 * invoked it, however, then another invocation will block until the first
	 * invocation is complete, after which it will return without effect.
	 */
	public abstract void close();

	/**
	 * Tells whether or not this TRNG <i>entropy source</i> is open.
	 */
	@Override
	public abstract boolean isOpen();

	// /////////////////////////////////////////////////////////////////////
	// /////////////////////// FACTORY METHODS /////////////////////////////
	// /////////////////////////////////////////////////////////////////////

	/**
	 * Returns a new <i>shared</i> Truerandom generator that implements the
	 * specified entropy gathering mechanism, or <i>True Random Number
	 * Generator</i> ({@linkplain TRNG}).
	 * 
	 * @param source
	 *            type of entropy source.
	 * 
	 * @return a new <i>shared</i> Truerandomness entropy generator.
	 */
	public static final Truerandomness shared(TRNG source) {
		return source.shared();
	}

	/**
	 * Returns a <b>unique</b> True-random Number Generator isolated to the
	 * current thread (<i>thread-local</i>) associated with specified entropy
	 * source. Any attempt to use this instance from another thread will throw
	 * {@link ConcurrentModificationException}.
	 * <p>
	 * Thread-local TRNG initializes when this method is first called; any
	 * further call will return the same instance for the same thread.
	 * 
	 * @param source
	 *            type of entropy source.
	 * @return a new <i>thread-local</i> Truerandom generator
	 * 
	 * @see TRNG#current()
	 */
	public static final Truerandomness current(TRNG source) {
		return source.current();
	}

	/**
	 * <i>TODO PROVISIONAL API, WORK IN PROGRESS:</i> Returns the specified
	 * True-random Number Generator using specified USB connection as a source
	 * of entropy.
	 * <p>
	 * This method should be used to connect {@link Truerandomness} with
	 * Hardware random number generator connected to base station via USB.
	 * 
	 * @param port
	 *            the specified USB connection name.
	 * 
	 * @see <a
	 *      href="http://en.wikipedia.org/wiki/Hardware_random_number_generator">Hardware
	 *      random number generator</a>
	 * 
	 */
	public static final Truerandomness fromUSB(String port) {
		throw new UnsupportedOperationException();
	}

	/**
	 * <i>TODO PROVISIONAL API, WORK IN PROGRESS:</i> Returns the specified
	 * True-random Number Generator using specified COMM connection as a source
	 * of entropy.
	 * <p>
	 * This method should be used to connect {@link Truerandomness} with
	 * Hardware random number generator connected to base station via COMM port.
	 * 
	 * @param port
	 *            the specified COMM connection name.
	 * 
	 * @see <a
	 *      href="http://en.wikipedia.org/wiki/Hardware_random_number_generator">Hardware
	 *      random number generator</a>
	 */
	public static final Truerandomness fromCOMM(String port) {
		throw new UnsupportedOperationException();
	}

	/**
	 * <i>TODO PROVISIONAL API, WORK IN PROGRESS:</i> The health <b>test
	 * function</b> determines that the TRNG mechanism continues to function
	 * correctly; An implementation <b>should</b> provide a capability to test
	 * the instantiate function on demand.
	 * <p>
	 * Known-answer tests shall be performed on the generate function before the
	 * first use of the function in an implementation.
	 * <p>
	 * TODO:
	 * <ol>
	 * <li>FIPS 140-1. statistical tests
	 * <li>Collect entropy gathering tests
	 * <li>Measurement of <i>min-entropy</i> (<i>H<sub>min</sub></i>).
	 * </ol>
	 * 
	 * @return <b>true</b> if entropy source perform correctly,
	 *         <code>false</code> otherwise.
	 */
	public boolean test() {
		return true;
	}

	/**
	 * Indicates whether some other object is "equal to" this one.
	 * 
	 * @param obj
	 *            the reference object with which to compare.
	 * @return <code>true</code> if this object is the same as the obj argument;
	 *         <code>false</code> otherwise.
	 */
	@Override
	public final boolean equals(Object obj) {
		return super.equals(obj);
	}

	/**
	 * Returns the <i>unique</i> hash code value of this
	 * <code>Truerandomness</code> (consistent with
	 * {@linkplain Truerandomness#equals(Object) equals}).
	 * 
	 * @return a hash code value for this object.
	 */
	@Override
	public final int hashCode() {
		return super.hashCode();
	}

}
