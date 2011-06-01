package org.randomness;

import java.io.Serializable;
import java.nio.ByteBuffer;
import java.nio.DoubleBuffer;
import java.nio.FloatBuffer;
import java.nio.IntBuffer;
import java.nio.LongBuffer;
import java.nio.channels.Channel;
import java.nio.channels.NonReadableChannelException;
import java.util.ConcurrentModificationException;
import java.util.List;
import java.util.ListIterator;
import java.util.Random;
import java.util.RandomAccess;

/**
 * This class specifies <i>Pseudorandom Number Generator</i> (PRNG) techniques
 * for the compute bits <i>deterministically</i> using an underlying algorithm
 * that, given the same initial state, always produces the same outputs.
 * <p>
 * A PRNG mechanism uses an algorithm that produces a sequence of pseudorandom
 * bits from an <i>initial internal state</i> that is determined by a seed that
 * is determined from the <i>entropy input</i>. The seed used to instantiate the
 * PRNG must contain sufficient entropy to provide an assurance of randomness.
 * Once the seed is provided and the initial internal state is determined, the
 * PRNG is said to be <i>instantiated</i>. The generate function generates
 * pseudorandom bits upon request, using the current internal state, and
 * generates a new internal state for the next request. Because of the
 * deterministic nature of the process, a PRNG is said to produce pseudorandom
 * bits, rather than random bits. Given the same seed inputs, algorithm always
 * produces the same outputs.
 * <h3>PRNG states</h3> The PRNG operate in following states:
 * <p>
 * <ul>
 * <li>
 * <i>Initial Internal State</i> (start of <i>stream</i>) - the collection of
 * stored information about a PRNG instantiation. The initial internal state
 * created when PRNG {@linkplain #reset() instantiated} at first time. To change
 * initial internal state the {@linkplain #reseed(ByteBuffer) reseed function}
 * should be called with another <i>seed</i> bytes.
 * <li><i>Initial Working State</i> - a result of apply the <i>initial internal
 * state</i> to instantiate algorithm. A subset of the initial internal state.
 * PRNG set's to initial working state every time when it's {@linkplain #reset
 * reseted}. The PRNG starting from the same initial working state will repeat
 * the same pseudorandom sequence.
 * <li><i>Working state</i> - a subset of the internal state, used by a PRNG
 * mechanism to produce pseudorandom bits at a given point in time. The working
 * state is updated to the next state prior to producing another pseudorandom
 * bits.
 * </ul>
 * <h3>PRNG mechanisms</h3> The PRNG mechanisms have four separate functions:
 * <p>
 * <ul>
 * <li>The {@linkplain Pseudorandomness#reset() instantiate function} acquires a
 * seed from entropy input to create <i>initial internal state</i>. Any
 * subsequent call of instantiate function reset's PRNG <i>working state</i> to
 * it's <i>initial internal state</i> so that subsequent
 * {@linkplain #read(ByteBuffer) reads} re-generate the same bytes. The
 * {@linkplain #reseed(ByteBuffer) reseed function} is used to change initial
 * internal state.
 * <li>The {@linkplain Pseudorandomness#reseed(ByteBuffer) reseed function}
 * acquires new entropy input to create a new seed and a new initial internal
 * state.
 * <li>The {@linkplain Pseudorandomness#read(ByteBuffer) generate function}
 * generates pseudorandom bits upon request, using the <i>current internal
 * state</i>, and generates a new internal state for the next request. <br>
 * All data generation methods are based on generate function. Concrete
 * implementations <strong>should</strong> implement this method and
 * <strong>should</strong> provide better / more performant essential
 * implementations of the other methods if the underlying PRNG supplies them.
 * <li>The {@linkplain Pseudorandomness#close() uninstantiate function} closes
 * this PRNG and zeroizes its internal state.
 * </ul>
 * <h3>Thread-local PRNG</h3>
 * The <i>thread-local</i> PRNG can be isolated in the
 * {@linkplain PRNG#current() current} thread; any attempt to access PRNG
 * functions from another thread will throw
 * {@link ConcurrentModificationException}. The pre-implemented PRNG instances
 * can be obtained in thread-local mode via both {@link PRNG#current()} or
 * {@link Pseudorandomness#current(PRNG)} factory-methods. For example:
 * <blockquote>
 * 
 * <pre>
 * Pseudorandomness mt = Pseudorandomness.current(PRNG.MERSENNE_TWISTER);
 * </pre>
 * 
 * </blockquote>
 * 
 * <p>
 * The <i>thread-local</i> PRNG has following properties:
 * <ul>
 * <li><i><b>Repeatable</b></i> - able to reproduce exactly the same sequence
 * several times depending on <i>initial internal state</i>. A key advantage of
 * deterministic PRNG is their ability to repeat exactly the same sequence of
 * random numbers without storing them. <i>Initial working state</i> used if
 * required to repeat all generated sequence (i.e., make sure that the same
 * random numbers are used for the same purposes in both cases). In other words
 * a subsequent call to the {@linkplain #reset() reset} method repositions this
 * PRNG at the last marked <i>initial working state</i> so that subsequent reads
 * re-generate the same bytes.
 * <li><i><b>Periodical</b></i> - due to the state being finite, the PRNG will
 * repeat at some point, and the <i> {@linkplain PRNG#period() period} </i> of a
 * RNG is how many numbers it can return before repeating. A PRNG using <i>n</i>
 * bits for its state has a period of at most <i>2<sup>n</sup></i>. A good RNG
 * must obviously have a very long period, to make sure that there is no chance
 * of wrapping around.
 * <li><i><b>Portable</b></i> - be easy to implement and behave the same way in
 * different software/hardware environments. In other words portability indicate
 * <i>predictability</i> on different software/hardware environments.
 * <li><i><b>Predictable</b></i> - starting a PRNG with the same seed allows
 * repeatable random sequences, which is very useful for debugging among other
 * things.
 * <ul>
 * <li><i><b>Predictable generation order</b></i> -
 * <code>Pseudorandomness</code> implementations <b>should</b> guarantee a
 * predictable order of generated bits. This means consistency in generated
 * pseudorandom sequence between set of {@link #read(ByteBuffer)
 * read(XXXBuffer)} operations and set of {@link #nextInt() nextXXX} operations.
 * In other words, the returned sequence of length <i>N</i> <b>should</b> be
 * equal regardless of the manner in which this sequence was obtained, from
 * <code>read(XXXBuffer)</code> or <code>nextXXX()</code>, where
 * <code>XXX</code> - the same primitive type (e.g. <code>long</code>,
 * <code>double</code>, <code>char</code>, <code>int</code> and others).
 * <li><i><b>Atomic</b></i> - the pseudorandom bitstring requires more than one
 * iteration of generate function <b>should</b> be created atomically from
 * consecutive iterations. For example, PRNG with <code>minlen = 4</code> should
 * has atomic {@link #nextLong()} and {@link #nextDouble()} methods.
 * </ul>
 * </ul>
 * <h3>Shared PRNG</h3>
 * 
 * If PRNG is not thread-local it automatically become <i>shared</i> across
 * multiple threads. The <i>shared</i> Pseudorandomness are safe for use by
 * multiple concurrent threads. The close method may be invoked at any time, as
 * specified by the {@link Channel} interface. Only one operation that involves
 * the PRNG's working state may be in progress at any given time; attempts to
 * initiate a second such operation while the first is still in progress will
 * block until the first operation completes. Other operations may proceed
 * concurrently; whether they in fact do so is dependent upon the underlying
 * implementation and is therefore unspecified. The pre-implemented
 * <i>shared</i> PRNG instances created via both
 * {@link Pseudorandomness#shared(PRNG)} or {@link PRNG#shared()}
 * factory-methods. <blockquote>
 * 
 * <pre>
 * Pseudorandomness mt = Pseudorandomness.shared(PRNG.MERSENNE_TWISTER);
 * </pre>
 * 
 * </blockquote>
 * <p>
 * 
 * The <i>shared</i> PRNG has following properties:
 * <ul>
 * <li><b><i>Repeatable</i></b>, <b><i>Periodical</i></b>,
 * <b><i>Portable</i></b>, <b><i>Predictable</i></b> - shared PRNG extends all
 * properties from <i>thread-local PRNG</i>. If shared PRNG in not accessed from
 * other threads it's behavior is identical to <i>thread-local</i> PRNG.
 * <li><i><b>Synchronized across multiple threads</b></i> - if another thread
 * has already initiated a generate operation upon this PRNG, however, then an
 * invocation of another generate operation will block until the first operation
 * is complete. <br>
 * <blockquote>
 * <code>gen.read(buffer); // synchronized with other read(XXXBuffer) and nextXXX calls </code>
 * <br>
 * <tab>
 * <code>gen.nextInt(); // synchronized with other nextXXX and read(XXXBuffer) calls </code>
 * <br>
 * </blockquote>
 * <li><i><b>Asynchronously closable</b></i> - the PRNG can be <i>asynchronously
 * closed</i>: If PRNG is blocked on an {@linkplain #read(ByteBuffer) generate
 * function}, then another thread may invoke the PRNG's {@link #close()} method.
 * This will stop generate function without throwing any exceptions after
 * generating next cycle of pseudorandom bytes. The generate function lock is
 * released, and {@linkplain #isOpen() close status} is set and can be checked
 * prior to next generation process.
 * </ul>
 * 
 * 
 * 
 * 
 * @author <a href="mailto:Anton.Kabysh@gmail.com">Anton Kabysh</a> - Code,
 *         Specification
 * @see <br>
 *      <a href="http://en.wikipedia.org/wiki/Pseudorandomness">Wikipedia -
 *      Pseudorandomness</a>
 * @see <br>
 *      <a href="http://en.wikipedia.org/wiki/Pseudorandom_number_generator">
 *      Wikipedia - Pseudorandom number generator</a>
 * @see <br>
 *      <a href="http://en.wikipedia.org/wiki/List_of_random_number_generators">
 *      Wikipedia - List of random number generators</a>
 */
public abstract class Pseudorandomness extends Randomness implements
		Serializable {
	/**
	 * 
	 */
	private static final long serialVersionUID = -4177007189293274256L;

	/**
	 * Initializes a new instance of this class.
	 */
	protected Pseudorandomness() {
	}

	private static final int SHUFFLE_THRESHOLD = 5;

	/**
	 * Creates <i>shared</i> Pseudorandomness using specified pre-implemented
	 * {@linkplain PRNG} algorithm.
	 * 
	 * @param prng
	 *            a specified PRNG algorithm
	 * 
	 * @see PRNG#shared()
	 * 
	 * @return the new PRNG <i>shared</i> instance.
	 */
	public static final Pseudorandomness shared(PRNG prng) {
		return prng.shared();
	}

	/**
	 * Creates a <b>unique</b> Pseudo-random Number Generator isolated to the
	 * current thread (<i>thread-local</i>). Any attempt to use this instance
	 * from another thread will throw {@link ConcurrentModificationException}.
	 * <p>
	 * Thread-local PRNG initializes when this method is first called; any
	 * further call will return the same instance for the same thread.
	 * 
	 * @param prng
	 *            a specified PRNG algorithm
	 * 
	 * @return the thread local instance of specified PRNG
	 * 
	 * @see PRNG#current()
	 */
	public static final Pseudorandomness current(PRNG prng) {
		return prng.current();
	}

	// ///////////////////////////////////////////////////////////
	// ///////////////// ABSTRACT PRNG FUNCTIONS /////////////////
	// ///////////////////////////////////////////////////////////

	/**
	 * The <b>instantiate function</b> creates the <i>initial working state</i>
	 * from <i>initial internal state</i> using the instantiate algorithm. A
	 * PRBG shall be instantiated prior to the {@linkplain #read(ByteBuffer)
	 * generation} of random bits. <h3>The instantiate function:</h3>
	 * <ol>
	 * <li>Checks the validity of the input parameters,
	 * <li>Determines any PRNG mechanism specific parameters (if required).
	 * <li>Obtains <i>seedlen</i> bytes of entropy from
	 * {@linkplain Pseudorandomness#getEntropyInput(int) entropy function},
	 * <li>Determines the initial internal state using the <i> instantiate
	 * algorithm</i>.
	 * </ol>
	 * <p>
	 * A subsequent call of instantiate function reset's PRNG <i>working
	 * state</i> to it's <i>initial internal state</i> so that subsequent
	 * {@link #read(ByteBuffer) reads} re-generate the same bytes.
	 * 
	 * <pre>
	 * Pseudorandomness gen = ...
	 * gen.read(buffer);
	 * 
	 * ...
	 * buffer.clear();
	 * gen.reset(); // restore to initial state;
	 * gen.read(buffer) // will generate the same pseudorandom sequence
	 * </pre>
	 * 
	 * This method may be invoked at any time. If another thread has already
	 * initiated a generate operation upon this PRNG, then an invocation of this
	 * method will block until the first operation is complete.
	 * 
	 * @throws NonReadableChannelException
	 *             if <i>entropy source</i> is closed.
	 */
	@Override
	public abstract void reset();

	/**
	 * The <b>reseed function</b> acquires a <i>seedlen</i> bytes to create new
	 * <i>internal state</i>. The {@linkplain #getEntropyInput(int) entropy
	 * input} required to seed or reseed a PRNG <b>shall</b> be obtained either
	 * directly or indirectly from an entropy source.
	 * <p>
	 * <h3>The reseed function:</h3>
	 * <ol>
	 * <li>Checks the validity of the input parameters,
	 * <li>Converts <code>seed</code> bytes to specified seed, and
	 * <li>Remember new <i>initial internal state</i> from the seed (discard
	 * previous, if present).
	 * <li>Using the instantiate algorithm determine the new <i>working
	 * state</i>.
	 * </ol>
	 * <p>
	 * The <i>seed</i> buffer should have no less than <i>seedlen</i> remaining
	 * bytes to read. In other words <code> seed.remaining() >= seedlen</code>
	 * or exception will be thrown.
	 * <p>
	 * This method may be invoked at any time. If another thread has already
	 * initiated a generate operation upon this PRNG, then an invocation of this
	 * method will block until the first operation is complete.
	 * 
	 * @param seed
	 *            a seed bytes which determine new working state using
	 *            instantiate algorithm.
	 * @return <code>this</code>
	 * 
	 * @throws NullPointerException
	 *             if <code>seed</code> is <code>null</code>
	 * @throws IllegalArgumentException
	 *             if <code>seed</code> bytes in {@link ByteBuffer} can't be
	 *             converted into <i>internal state</i>. In other words <code>
	 *             seed</code> contains no enough bytes to be converted into
	 *             internal state.
	 * @see PRNG#seedlen() Seed sizes of pre-implemented PRNG's
	 * @see <br> {@link PRNG#DEFAULT_ENTROPY_INPUT}
	 */
	public abstract Pseudorandomness reseed(ByteBuffer seed);

	/**
	 * Reseed's this PRNG creating new <i>internal state</i> from the specified
	 * seed bytes.
	 * <p>
	 * Otherwise this method behaves exactly as specified in the
	 * {@linkplain #reseed(ByteBuffer) reseed function}.
	 * 
	 * @param seed
	 *            the seed bytes
	 * @return <code>this</code>
	 * @throws IllegalArgumentException
	 *             if <code>seed</code> bytes length is less than <i>seedlen</i>
	 *             value.
	 * 
	 */
	public final Pseudorandomness reseed(byte[] seed) {
		return reseed(ByteBuffer.wrap(seed));
	}

	/**
	 * Creates new <i>initial internal state</i> using
	 * {@linkplain #reseed(ByteBuffer) reseed function} obtaining <i>seedlen</i>
	 * bytes from {@linkplain #getEntropyInput(int) entropy input}.
	 * <p>
	 * Discard's a previous <i>initial internal state</i>, if present, and set's
	 * the new one.
	 * <p>
	 * This method may be invoked at any time. If another thread has already
	 * initiated a generate operation upon this PRNG, then an invocation of this
	 * method will block until the first operation is complete.
	 * 
	 * @return this PRNG with new initial internal state.
	 * 
	 * @throws NonReadableChannelException
	 *             if <i>entropyInput</i> is closed.
	 */
	public final Pseudorandomness reseed() {
		this.reseed(ByteBuffer.wrap(getEntropyInput(seedlen())));
		return this;
	}

	/**
	 * The <b>generate function</b> is used to generate the requested
	 * pseudorandom bits after {@linkplain Pseudorandomness#reset()
	 * instantiation} or {@linkplain Pseudorandomness#reseed(ByteBuffer)
	 * reseeding} using the <i>generate algorithm</i>.
	 * <p>
	 * In other words, transfers a sequence generated bytes from this PRNG into
	 * the given buffer. An attempt is made to generate up to <i>r</i> bytes
	 * from PRNG, where <i>r</i> is the number of bytes <i>remaining</i> in the
	 * buffer, that is, <tt>buffer.remaining()</tt>, at the moment this method
	 * is invoked.
	 * <p>
	 * This method may be invoked at any time. If another thread has already
	 * initiated a generate operation upon this PRNG, then an invocation of this
	 * method will block until the first operation is complete.
	 * <h3>The generate function:</h3>
	 * <ol>
	 * <li>Checks the validity of the current state.
	 * <li>For every generate iteration:
	 * <ul>
	 * <li>Generates the <i>minlen</i> bytes using the generate algorithm.
	 * <li>Updates the working state.
	 * <li>Transfers generated minlen bytes into buffer.
	 * </ul>
	 * <ul>
	 * <li>If generator is closed - stop generation function and return total
	 * generated bytes.
	 * </ul>
	 * <li>Returns the requested pseudorandom bytes to the consuming
	 * application.
	 * </ol>
	 * 
	 * @param buffer
	 *            The buffer into which random bytes are to be transferred
	 * 
	 * @return The number of bytes generated, possibly zero.
	 * 
	 * @throws NullPointerException
	 *             if <code>buffer</code> is <code>null</code>.
	 * 
	 */
	@Override
	public abstract int read(ByteBuffer buffer);

	/**
	 * Transfers a sequence of generated pseudorandom <code>int</code>'s from
	 * this PRNG into the given buffer.
	 * <p>
	 * In other words, transfers a sequence generated integers from this PRNG
	 * into the given buffer. An attempt is made to generate up to <i>r</i>
	 * bytes from PRNG, where <i>r</i> is the number of integers
	 * <i>remaining</i> in the buffer, that is, <tt>buffer.remaining()</tt>, at
	 * the moment this method is invoked.
	 * <p>
	 * Otherwise this method behaves exactly as specified in the
	 * {@linkplain #read(ByteBuffer) generate function}.
	 * 
	 * @param intBuffer
	 *            The buffer into which random integers are to be transferred
	 * @return The number of <code>int</code>'s read, possibly zero.
	 */
	public abstract int read(IntBuffer intBuffer);

	/**
	 * Transfers a sequence of generated pseudorandom <code>float</code>'s from
	 * this PRNG into the given buffer.
	 * <p>
	 * In other words, transfers a sequence generated floating point values from
	 * this PRNG into the given buffer. An attempt is made to generate up to
	 * <i>r</i> bytes from PRNG, where <i>r</i> is the number of integers
	 * <i>remaining</i> in the buffer, that is, <tt>buffer.remaining()</tt>, at
	 * the moment this method is invoked.
	 * <p>
	 * This method behaves exactly as specified in the
	 * {@linkplain #read(ByteBuffer) generate function}.
	 * 
	 * @param floatBuffer
	 *            The buffer into which random floating point values are to be
	 *            transferred
	 * @return The number of <code>float</code>'s read, possibly zero.
	 */
	public abstract int read(FloatBuffer floatBuffer);

	/**
	 * Transfers a sequence of generated <code>long</code>'s from this PRNG into
	 * the given buffer.
	 * <p>
	 * In other words, transfers a sequence generated integers from this PRNG
	 * into the given buffer. An attempt is made to generate up to <i>r</i>
	 * bytes from PRNG, where <i>r</i> is the number of integers
	 * <i>remaining</i> in the buffer, that is, <tt>buffer.remaining()</tt>, at
	 * the moment this method is invoked.
	 * <p>
	 * This method behaves exactly as specified in the
	 * {@linkplain #read(ByteBuffer) generate function}.
	 * 
	 * @param longBuffer
	 *            The buffer into which random <code>long</code> values are to
	 *            be transferred.
	 * @return The number of <code>long</code>'s read, possibly zero.
	 */
	public abstract int read(LongBuffer longBuffer);

	/**
	 * Transfers a sequence of generated <code>double</code>'s from this PRNG
	 * into the given buffer.
	 * <p>
	 * In other words, transfers a sequence generated floating point double's
	 * from this PRNG into the given buffer. An attempt is made to generate up
	 * to <i>r</i> bytes from PRNG, where <i>r</i> is the number of integers
	 * <i>remaining</i> in the buffer, that is, <tt>buffer.remaining()</tt>, at
	 * the moment this method is invoked.
	 * <p>
	 * This method behaves exactly as specified in the
	 * {@linkplain #read(ByteBuffer) generate function}.
	 * 
	 * @param doubleBuffer
	 *            The buffer into which random <code>double</code>'s are to be
	 *            transferred
	 * @return The number of <code>double</code>'s read, possibly zero.
	 */
	public abstract int read(DoubleBuffer doubleBuffer);

	/**
	 * Attempts to read from this PRNG into the given buffer, starting at the
	 * given file position if <i>generate function</i> is not owned by other
	 * thread.
	 * <p>
	 * For thread-local PRNG this method behaves exactly as specified in the
	 * {@linkplain #read(ByteBuffer) generate function}.
	 * 
	 * @param buffer
	 *            The buffer into which random bytes are to be transferred.
	 * @return The number of bytes read from PRNG, possibly zero, or <tt>-1</tt>
	 *         if the PRNG has already blocked on other thread.
	 */
	@Override
	public abstract int tryRead(ByteBuffer buffer);

	/**
	 * Returns a deep copy of this pseudorandomness with identical producing
	 * output <i>(optional operation)</i>.
	 * <p>
	 * This metod <b>shoud be</b> overriden in subclasses, or
	 * {@link UnsupportedOperationException} will be thrown. The returned copy
	 * and original PRNG <b>should be</b> consistent at {@link #equals(Object)}
	 * (be equal) and {@link #hashCode()} (has the same hash code) methods.
	 * <p>
	 * This metod is overriden and implemented in all {@link PRNG} boundled
	 * implementations.
	 * 
	 * @return the deep copy of this <code>Pseudorandomness</code>
	 *         {@linkplain #equals(Object) equal} to original
	 * 
	 * @throws UnsupportedOperationException
	 *             if not overriden
	 * 
	 * @throws NonReadableChannelException
	 *             if channel is closed (no state to copy)
	 */
	public Pseudorandomness copy() {
		if (!isOpen())
			throw new NonReadableChannelException();

		throw new UnsupportedOperationException();
	};

	/**
	 * Tells whether or not this PRNG is open to generate pseudorandom bytes.
	 * <p>
	 * If PRNG is closed, any further attempt to invoke generate operations upon
	 * it will cause a {@link NonReadableChannelException} to be thrown.
	 * 
	 * @return <code>false</code> if PRNG is not instantiated yet or
	 *         {@linkplain #close() closed}, <code>true</code> otherwise.
	 */
	@Override
	public abstract boolean isOpen();

	/**
	 * The <b>uninstantiate function</b> closes this PRNG and zeroizes its
	 * internal state. If PRNG is closed, any further attempt to invoke generate
	 * operations upon it will cause a {@link NonReadableChannelException} to be
	 * thrown. The closing status can be checked at run-time via
	 * {@link #isOpen()} method. Opposite to {@linkplain Randomness#reset()
	 * instantiate} function.
	 * <p>
	 * The close method eliminate all PRNG internal state, so any further
	 * operations dealing with PRNG internal state will throws
	 * {@link NonReadableChannelException}. For example, PRNG can't be
	 * {@linkplain #copy() copied}, generate any pseudorandom output, not equals
	 * to itself, but still has a hash code.
	 * <p>
	 * <h3>Asynchronous Closability</h3><br>
	 * If PRNG is blocked on an {@linkplain #read(ByteBuffer) generate function}
	 * , then another thread may invoke (asynchronously) the PRNG's close
	 * method. This will stop generate function without throwing any exceptions
	 * after generating next cycle of pseudorandom bytes The generate function
	 * lock is released, and {@linkplain #isOpen() close status} is set and can
	 * be checked prior to next generation process.
	 * <p>
	 * This method may be invoked at any time. Interrupting a PRNG that is not
	 * generate random bytes need not have any effect. If this PRNG is already
	 * closed then invoking this method has no effect.
	 */
	@Override
	public abstract void close();

	/**
	 * <i>Minlen</i> it is the minimum block of bytes essentially produced per
	 * one iteration of generate function <i>(optional operation)</i>.
	 * <p>
	 * This method <b> should be </b> overriden to provide additional
	 * information about PRNG for most essential generation process.
	 * <p>
	 * If method is not overriden, it returns defautl value, equal to 4 bytes
	 * (minimum from all minlens of all {@link PRNG} implementations).
	 * 
	 * @return amount of bytes generated on each iteration of generate function
	 */
	@Override
	public int minlen() {
		return INT_SIZE_BYTES;
	}

	/**
	 * Return's initial <i>seed length</i> used by underlying PRNG algorithm in
	 * bytes.
	 * 
	 * @return the seed length
	 */
	protected abstract int seedlen();

	/**
	 * A <b>entropy function</b> is used to obtain <i>entropy input</i>.
	 * <p>
	 * Returns the input to a PRNG mechanism of a string of bits that contains
	 * entropy; that is, the entropy input is digitized and has been assessed
	 * prior to use as input.
	 * <p>
	 * Entropy is obtained from an {@linkplain Truerandomness entropy source}.
	 * The entropy input required to seed or reseed a PRNG <b>shall</b> be
	 * obtained either directly or indirectly from an entropy source.
	 * <p>
	 * Note that an implementation may choose to define this functionality
	 * differently. The default entropy input is specified by
	 * {@link PRNG#DEFAULT_ENTROPY_INPUT} variable. The user may specify
	 * external seeds at {@link #reseed(ByteBuffer)} function.
	 * 
	 * 
	 * @param minEntropy
	 *            number bytes of entropy.
	 * 
	 * @return a byte array containing <i>min_entropy</i> bytes of entropy.
	 */
	protected byte[]/* ByteBuffer */getEntropyInput(int minEntropy) {

		final Randomness entropySource = PRNG.DEFAULT_ENTROPY_INPUT.get();
		if (entropySource instanceof NativeEntropy) {
			NativeEntropy nativeEntropy = (NativeEntropy) entropySource;
			return nativeEntropy.source.generateSeed(minEntropy);
		} else {
			byte[] entropy = new byte[minEntropy];
			entropySource.read(ByteBuffer.wrap(entropy));
			return entropy;
		}
	}

	/**
	 * Returns the hash code value for this generator (consistent with
	 * {@linkplain #equals(Object) equals}) <i>(optional operation)</i>.
	 * <p>
	 * This method <b>should be</b> overridden is subclasses to correspond
	 * complete {@link Pseudorandomness} specifications.
	 * <p>
	 * <h5>Contract</h5>
	 * For two <code>Pseudorandomness</code>, {@linkplain #equals(Object) equal
	 * with each other}, invocation of this method must return the same hash
	 * code value. In other words, if two <code>Pseudorandomness</code> has same
	 * <i>algorithm</i> and <i>internal state</i> producing the same output,
	 * they must have same hash code.
	 * <p>
	 * Because hash codes of <code>Pseudorandomness</code> are state-dependent,
	 * it is inadvisable to use <code>Pseudorandomness</code> as keys in hash
	 * maps or similar data structures.
	 * <p>
	 * If PRNG is closed, than system hash code for PRNG object should be
	 * returned.
	 * 
	 * @return The current hash code of this <code>Pseudorandomness</code>.
	 * 
	 * @throws UnsupportedOperationException
	 *             if not overriden
	 */
	@Override
	public int hashCode() {
		throw new UnsupportedOperationException();
	};

	/**
	 * Tells whether or not this <code>Pseudorandomness</code> is equal to
	 * another object (consistent with {@link #hashCode() hashCode}) <i>
	 * (optional operation)</i>.
	 * <p>
	 * This method <b>should be</b> overridden is subclasses to correspond
	 * complete {@link Pseudorandomness} specifications.
	 * <p>
	 * <h5>Contract</h5>
	 * The two <code>Pseudorandomness</code> are equal if and only if they has
	 * same <i>algorithm</i> and <i>internal state</i> such, any next produced
	 * output is identical. Implementation of this method <b>should be</b>
	 * consistent wiht the {@link #hashCode()} and {@link #toString()} methods.
	 * <p>
	 * If PRNG is closed they has no internal state, so
	 * <code>rand.equal(rand)</code> returns <code>false</code>.
	 * 
	 * @return <code>true</code> if two Pseudorandomness are identical,
	 *         <code>false</code> otherwise.
	 * 
	 * @throws UnsupportedOperationException
	 *             if not overriden
	 */
	@Override
	public boolean equals(Object obj) {
		throw new UnsupportedOperationException();
	};

	// //////////////////////////////////////////////////////////
	// //////////////// GENERATE METHODS ////////////////////////
	// //////////////////////////////////////////////////////////
	/**
	 * Returns the next pseudorandom, Gaussian ("normally") distributed
	 * <code>double</code> value with mean <code>0.0</code> and standard
	 * deviation <code>1.0</code> from this random number generator's sequence.
	 * 
	 * @return the next pseudorandom, Gaussian ("normally") distributed
	 *         <code>double</code> value with mean <code>0.0</code> and standard
	 *         deviation <code>1.0</code> from this random number generator's
	 *         sequence
	 */
	public final double nextGaussian() {
		// inspired from org.apache.commons.math.random.BitsStreamGenerator
		final double random;
		if (Double.isNaN(nextGaussian)) {
			// generate a new pair of gaussian numbers
			final double x = nextDouble();
			final double y = nextDouble();

			final double alpha = 2 * Math.PI * x;
			final double r = Math.sqrt(-2 * Math.log(y));
			random = r * Math.cos(alpha);
			nextGaussian = r * Math.sin(alpha);
		} else {
			// use the second element of the pair already generated
			random = nextGaussian;
			nextGaussian = Double.NaN;
		}

		return random;

	}

	/**
	 * Returns the next pseudorandom, Gaussian ("normally") distributed
	 * <code>double</code> value with the given mean, <code>mu</code> and the
	 * given standard deviation, <code>sigma</code>.
	 * 
	 * @param mu
	 *            the mean of the distribution
	 * @param sigma
	 *            the standard deviation of the distribution
	 * @return the random Normal value
	 * @throws IllegalArgumentException
	 *             if {@code sigma <= 0}.
	 */
	public final double nextGaussian(double mu, double sigma) {
		if (sigma <= 0) {
			throw new IllegalArgumentException("Illegal sigma value: " + sigma);
		}
		return sigma * nextGaussian() + mu;
	}

	/** Next gaussian. */
	private double nextGaussian = Double.NaN;

	/**
	 * Returns a double value with a positive sign, greater than or equal to 0.0
	 * and less than 1.0. Returned values are chosen pseudorandomly with
	 * (approximately) uniform distribution from that range.
	 * 
	 * @return a pseudorandom double greater than or equal to 0.0 and less than
	 *         1.0.
	 */
	public final double random() {
		return nextDouble();
	}

	/**
	 * Returns a uniformly distributed random number in the closed interval
	 * <tt>[from,to]</tt> (including <tt>from</tt> and <tt>to</tt>).
	 * 
	 * @param from
	 *            low border of interval (included)
	 * @param to
	 *            hight border of interval (included)
	 * 
	 * @throws IllegalArgumentException
	 *             if <tt>from >= to</tt>.
	 * @return next generated uniformly distributed random number in interval
	 *         <tt>[from,to]</tt>.
	 */
	public final int nextInt(int from, int to) {
		// The implementation is inspired from Cern's Colt Jet Random
		if (from >= to)
			throw new IllegalArgumentException("upper bound (" + to
					+ ") must be greater than lower bound (" + from + ")");

		return (int) (from + ((1 + to - from) * nextFloat()));
	}

	/**
	 * Returns a uniformly distributed random floating point number in the open
	 * interval <tt>(from,to)</tt> (excluding <tt>from</tt> and <tt>to</tt>).
	 * 
	 * @param from
	 *            low border of interval (excluded)
	 * 
	 * @param to
	 *            hight border of interval (excluded)
	 * 
	 * @throws IllegalArgumentException
	 *             if <tt>from >= to</tt>.
	 * @return next generated uniformly distributed random floating point in
	 *         interval <tt>[from,to]</tt>.
	 */
	public final double nextDouble(double from, double to) {
		if (from >= to)
			throw new IllegalArgumentException("upper bound (" + to
					+ ") must be greater than lower bound (" + from + ")");

		// The implementation is inspired from Cern's Colt Jet Random
		return from + (to - from) * nextDouble();
	}

	/**
	 * Returns a uniformly distributed random floating point number in the open
	 * interval <tt>(from,to)</tt> (excluding <tt>from</tt> and <tt>to</tt>).
	 * 
	 * @param from
	 *            low border of interval (excluded)
	 * 
	 * @param to
	 *            hight border of interval (excluded)
	 * 
	 * @throws IllegalArgumentException
	 *             if <tt>from >= to</tt>.
	 * @return next generated uniformly distributed random floating point in
	 *         interval <tt>[from,to]</tt>.
	 */
	public final float nextFloat(float from, float to) {
		if (from >= to)
			throw new IllegalArgumentException("upper bound (" + to
					+ ") must be greater than lower bound (" + from + ")");

		// The implementation is inspired from Cern's Colt Jet Random
		return from + (to - from) * nextFloat();
	}

	/**
	 * Returns a uniformly distributed random number in the closed interval
	 * <tt>[from,to]</tt> (including <tt>from</tt> and <tt>to</tt>).
	 * 
	 * @param from
	 *            low border of interval (included)
	 * @param to
	 *            hight border of interval (included)
	 * 
	 * @throws IllegalArgumentException
	 *             if <tt>from >= to</tt>.
	 * @return next generated uniformly distributed random number in interval
	 *         <tt>[from,to]</tt>.
	 */
	public final long nextLong(long from, long to) {
		if (from >= to)
			throw new IllegalArgumentException("upper bound (" + to
					+ ") must be greater than lower bound (" + from + ")");

		// The implementation is inspired from Cern's Colt Jet Random

		/*
		 * Doing the thing turns out to be more tricky than expected. avoids
		 * overflows and underflows. treats cases like from=-1, to=1 and the
		 * like right. the following code would NOT solve the problem: return
		 * (long) (Doubles.randomFromTo(from,to));
		 * 
		 * rounding avoids the unsymmetric behaviour of casts from double to
		 * long: (long) -0.7 = 0, (long) 0.7 = 0. checking for overflows and
		 * underflows is also necessary.
		 */

		// first the most likely and also the fastest case.
		if (from >= 0 && to < Long.MAX_VALUE) {
			return from + (long) (nextDouble(0.0, to - from + 1));
		}

		// would we get a numeric overflow?
		// if not, we can still handle the case rather efficient.
		double diff = ((double) to) - (double) from + 1.0;
		if (diff <= Long.MAX_VALUE) {
			return from + (long) (nextDouble(0.0, diff));
		}

		// now the pathologic boundary cases.
		// they are handled rather slow.
		long random;
		if (from == Long.MIN_VALUE) {
			if (to == Long.MAX_VALUE) {
				// return Math.round(nextDoubleFromTo(from,to));
				int i1 = nextInt(Integer.MIN_VALUE, Integer.MAX_VALUE);
				int i2 = nextInt(Integer.MIN_VALUE, Integer.MAX_VALUE);
				return ((i1 & 0xFFFFFFFFL) << 32) | (i2 & 0xFFFFFFFFL);
			}
			random = Math.round(nextDouble(from, to + 1));
			if (random > to)
				random = from;
		} else {
			random = Math.round(nextDouble(from - 1, to));
			if (random < from)
				random = to;
		}
		return random;
	}

	/**
	 * Randomly permute the specified list using this PRNG. All permutations
	 * occur with equal likelihood assuming that the source of randomness is
	 * fair.
	 * 
	 * <pre>
	 * Pseudorandomness rand = ...
	 * rand.shuffle(Arrays.asList(200,300,212,111,6,2332));
	 * </pre>
	 * 
	 * This implementation traverses the list backwards, from the last element
	 * up to the second, repeatedly swapping a randomly selected element into
	 * the "current position". Elements are randomly selected from the portion
	 * of the list that runs from the first element to the current position,
	 * inclusive.
	 * <p>
	 * This method runs in linear time. If the specified list does not implement
	 * the {@link RandomAccess} interface and is large, this implementation
	 * dumps the specified list into an array before shuffling it, and dumps the
	 * shuffled array back into the list. This avoids the quadratic behavior
	 * that would result from shuffling a "sequential access" list in place.
	 * 
	 * @param list
	 *            the list to be shuffled.
	 * 
	 * @see Collections#shuffle(List);
	 * 
	 * @throws UnsupportedOperationException
	 *             if the specified list or its list-iterator does not support
	 *             the <tt>set</tt> operation.
	 */
	@SuppressWarnings("unchecked")
	public final void shuffle(List<?> list) {
		// The implementation is inspired from Sun's Collections.shuffle
		final int size = list.size();

		if (size == 0)
			return;

		if (size < SHUFFLE_THRESHOLD || list instanceof RandomAccess) {
			for (int i = size; i > 1; i--)
				swap(list, i - 1, nextInt(i));
		} else {
			Object arr[] = list.toArray();

			// Shuffle array
			for (int i = size; i > 1; i--)
				swap(arr, i - 1, nextInt(i));

			// Dump array back into list
			@SuppressWarnings("rawtypes")
			ListIterator it = list.listIterator();
			for (int i = 0; i < arr.length; i++) {
				it.next();
				it.set(arr[i]);
			}
		}
	}

	/**
	 * Swaps the elements at the specified positions in the specified list. (If
	 * the specified positions are equal, invoking this method leaves the list
	 * unchanged.)
	 * 
	 * @param list
	 *            The list in which to swap elements.
	 * @param i
	 *            the index of one element to be swapped.
	 * @param j
	 *            the index of the other element to be swapped.
	 * @throws IndexOutOfBoundsException
	 *             if either <tt>i</tt> or <tt>j</tt> is out of range (i &lt; 0
	 *             || i &gt;= list.size() || j &lt; 0 || j &gt;= list.size()).
	 */
	@SuppressWarnings({ "rawtypes", "unchecked" })
	private static final void swap(List<?> list, int i, int j) {
		final List l = list;
		l.set(i, l.set(j, l.get(i)));
	}

	/**
	 * Swaps the two specified elements in the specified array.
	 */
	private static final void swap(Object[] arr, int i, int j) {
		Object tmp = arr[i];
		arr[i] = arr[j];
		arr[j] = tmp;
	}

	/**
	 * Represents this PRNG as <code>java.util.Random</code>.
	 * <p>
	 * This method convert this PRNG into <code>java.util.Random</code>
	 * instance, to be used instead it in java legacy code. For example:
	 * <p>
	 * <code>BigInteger big = new BigInteger(128, Randomness.from(TRNG.NATIVE).asRandom());
</code>
	 * <p>
	 * <b>Note: Calling of {@link Random#setSeed(long)} has the same semantis as
	 * {@link #reseed(ByteBuffer)} with byte buffer containing 8 bytes from
	 * <code>long </code> seed value.</b>
	 * <p>
	 * The view is typically part of the RBG itself (created only once) and
	 * every call return this instance.
	 * 
	 * @see Cryptorandomness#asRandom()
	 * 
	 * @return view as <code>java.util.Random</code> over this PRNG.
	 */
	public final Random asRandom() {
		if (random == null)
			random = new Randomness.AsRandom();
		return random;
	}

	/**
	 * Returns the name of the <i>algorithm</i> implemented by this PRNG <i>
	 * (optional operation)</i>.
	 * <p>
	 * This method <b>should be</b> overridden to provide additional information
	 * about PRNG.
	 * <p>
	 * The {@link PRNG} implementations {@link #toString()} value, consistent
	 * with {@link PRNG#valueOf(String)} and vice-versa.
	 * 
	 * @return the name of the algorithm, or <i>UNKNOWN</i> if the algorithm
	 *         name cannot be determined (default value).
	 */
	@Override
	public String toString() {
		return "UNKNOWN";
	};

	/**
	 * Indicate if PRNG supports different periods.
	 * 
	 * @author Anton Kabysh
	 */
	interface Multiperiodical {
		int period();
	}

	public long nextLong1() {
		// inspired by org.apache.commons.math.random.BitsStreamGenerator;
		final long high = ((long) nextInt()) << 32;
		final long low = ((long) nextInt()) & 0xffffffffL;
		return high | low;
	}

	float nextFloat1() {
		// inspired by org.apache.commons.math.random.BitsStreamGenerator;
		return (nextInt() >>> 8) * 0x1.0p-23f;
	}

	double nextDouble1() {
		// inspired by org.apache.commons.math.random.BitsStreamGenerator;
		final long high = ((long) (nextInt() >>> 8)) << 26;
		final int low = (nextInt() >>> 8);
		return (high | low) * 0x1.0p-52d;
	}

	/**
	 * <i>TODO PROVISIONAL API, WORK IN PROGRESS:</i> Reinitializes the PRNG to
	 * the beginning of its next substream <i>(optional operation)</i>.
	 * 
	 * @return next substream
	 */
	public Pseudorandomness next() {
		throw new UnsupportedOperationException();
	}
}
