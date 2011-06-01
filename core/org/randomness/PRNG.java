package org.randomness;

import java.nio.ByteBuffer;
import java.nio.DoubleBuffer;
import java.nio.FloatBuffer;
import java.nio.IntBuffer;
import java.nio.LongBuffer;
import java.security.SecureRandom;
import java.util.ConcurrentModificationException;
import java.util.List;
import java.util.ListIterator;
import java.util.Random;
import java.util.RandomAccess;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

/**
 * List of implemented <i>Pseudo Random Number Generators</i> that produces a
 * deterministic, periodic and predictable pseudorandom sequence of bits from a
 * initial value called a seed. It contrast with a {@linkplain TRNG TRNG}
 * process.
 * <p>
 * PRNGs are not suitable for applications where it is important that the
 * numbers are really unpredictable, such as data encryption and gambling. Note
 * that none of these generators are suitable for cryptography. See
 * <i>Cryptographically Secure Pseudorandom Number Generators</i> (
 * {@linkplain CSPRNG CSPRNG}) for that purposes. Non-cryptographically secure
 * methods are usually faster than cryptographic methods, but should not be used
 * when security is needed, hence the classification.
 * <p>
 * <h3>PRNG Properties</h3>
 * Due to computational needs, memory requirements, security needs, and desired
 * random number "quality", there are many different RNG algorithms. No one
 * algorithm is suitable for all cases, in the same way that no sorting
 * algorithm is best in all situations. In common, each PRNG can be described in
 * following properties:
 * <p>
 * <blockquote>
 * <table border="1" cellpadding="6">
 * <caption>Table:<b> Properties of implemented Pseudoranom Number
 * Generators</b> </caption>
 * <tr>
 * <th>Name</th>
 * <th> {@linkplain Randomness#minlen() Minlen}</th>
 * <th> {@linkplain #outlen() Outlen}</th>
 * <th> {@linkplain #period() Period}</th>
 * <th> {@linkplain #seedlen() Seedlen}</th>
 * <th>Statelen</th>
 * <th>License</th>
 * <th>Category</th>
 * <th>Support Streams</th>
 * </tr>
 * <tr>
 * <td><b>Name of the PRNG.</b></td>
 * <td><b>Minlen</b> - size of pseudorandom bitstring in bytes, generated per
 * iteration.</td>
 * <td><b>Output lenght</b> it is a size of PRNG <i>generation cycle</i>.
 * Generation cycle - it is a number of bytes generated between two
 * modifications of working state. The generation cycle value implements idea of
 * block generation. Each block can be directly transferred into
 * {@link ByteBuffer}s</td>
 * <td>
 * <b>Period </b>is a variable <code>N</code> indicate period of PRNG in form of
 * <code>2<sup>N<sup></code>.
 * <td><b>Seedlen</b> is a size of PRNG <i>seed</i> in bytes.</td>
 * <td><b>Statelen</b> is a size of PRNG <i>working state</i> of in bytes. The
 * full required memory is equal to sum of <i>seedlen</i> and <i>statelen</i>.
 * <p>
 * <td><b>Name</b> of the license under source code of PRNG is distributed.</td>
 * <td>Field of usage. Features, comments, advantages and disadvantages.</td>
 * <td>Indicate if supports streams concept proposed by Pierre L'Ecuyer.
 * </tr>
 * </table>
 * </blockquote>
 * <h3>PRNG usage:</h3>
 * PRNGs characteristics make it suitable for applications where many numbers
 * are required and where it is useful that the same sequence can be replayed
 * easily. Popular examples of such applications are:
 * <ul>
 * <li>AI algorithms like genetic algorithms and automated opponents.
 * <li>Random game content and level generation.
 * <li>Simulation of complex phenomena such as weather and fire.
 * <li>Weather simulation and other statistical physics testing.
 * <li>Modeling
 * <li>Numerical methods such as Monte-Carlo integration.
 * <li>
 * <li>Until recently primality proving used randomized algorithms.
 * <li>Optimization algorithms use random numbers significantly: simulated
 * annealing, large space searching, and combinatorial searching.
 * </ul>
 * <p>
 * <h3>Thanks to:</h3>
 * 
 * @author <b><a href="mailto:anton.kabysh@gmail.com">Anton Kabysh</a></b>
 *         (randomness adaptation)
 * @author <br>
 *         <b>Daniel Dyer</b> (<a
 *         href="https://uncommons-maths.dev.java.net">uncommons-math</a>
 *         versions of {@linkplain PRNG#CELLULAR_AUTOMATON cellular automaton},
 *         {@linkplain PRNG#CMWC4096 CMWC4096}, and {@linkplain PRNG#XOR_SHIFT }
 *         generators)
 * @author <br>
 *         <b>George Marsaglia</b> (author and original C version of
 *         {@linkplain PRNG#CMWC4096 CMWC4096} and {@linkplain PRNG#XOR_SHIFT
 *         XOR shift} generators)
 * @author <br>
 *         <b>Neil Coffey</b> (java port of <a href=
 *         "http://www.amazon.com/gp/product/0521880688?ie=UTF8&amp;tag=javamex-20&amp;linkCode=as2&amp;camp=1789&amp;creative=9325&amp;creativeASIN=0521880688"
 *         >Numerical Recipes</a> {@linkplain PRNG#COMBINED combined} generator)
 * @author <br>
 *         <b>Frank Yellin</b> (implementation of <code>java.util.Random</code>
 *         {@linkplain #LCG} from Java SDK)
 * @author <br>
 *         <b>Makoto Matsumoto</b> and <b>Takuji Nishimura</b> (idea and
 *         authors: {@linkplain PRNG#MT MT19937}, {@linkplain PRNG#MT64 MT19937
 *         64-bit version}, {@linkplain PRNG#SFMT SFTM} and
 *         {@linkplain PRNG#dSFMT2 dSFMT2} random generators)
 * @author <br>
 *         <b>Mutsuo Saito</b> (coautor of {@linkplain PRNG#SFMT SFMT} and
 *         {@linkplain PRNG#dSFMT2 dSFMT2} generators)
 * @author <br>
 *         <b><a href="http://www.cs.gmu.edu/~sean/research/">Sean Luke </a></b>
 *         (Fast Mersenne Twister java implementation)
 * @author <br>
 *         <b>Nick Galbreath</b> (implementations of {@linkplain #MT64 MT64},
 *         {@linkplain #BAILEY_CRANDALL Bailey-Crandall} and
 *         {@linkplain #CELLULAR_AUTOMATON_192_RULE_30 Rule30, 192 Cells CA
 *         PRNG} from <a href="http://code.google.com/p/javarng/">javarng</a>)
 * @author <br>
 *         <b>Adrian King</b> (java {@linkplain #SFMT} implementation)
 * @author <br>
 *         <b>Fran&ccedil;ois Panneton</b>, <b>Pierre L'Ecuyer</b> and <b>Makoto
 *         Matsumoto</b> (authors of <i>WELL</i> generators family.)
 * @author <br>
 *         <b>Doug Lea</b> (idea and implementation of <code>
 *         java.util.concurrent.ThreadLocalRandom</code>)
 * 
 * @see TRNG True Random Number Generators
 * @see CSPRNG Cryptographically Secure Pseudorandom Number Generators
 */
public enum PRNG /* implements , Closeable */{

	/**
	 * Extra fast <a
	 * href="http://home.southernct.edu/~pasqualonia1/ca/report.html"
	 * target="_top">Cellular automaton pseudorandom number generator</a>
	 * developed by Tony Pasqualoni.
	 * <p>
	 * <blockquote>
	 * <table border="1" cellpadding="6">
	 * <caption>Table:<b> Properties of Cellular automaton pseudorandom number
	 * generator</b> </caption>
	 * <tr>
	 * <th>Name</th>
	 * <th>Precision</th>
	 * <th>Minlen</th>
	 * <th>Outlen</th>
	 * <th>Period</th>
	 * <th>Seedlen</th>
	 * <th>Statelen</th>
	 * <th>License</th>
	 * <th>Category</th>
	 * 
	 * </tr>
	 * <tr>
	 * <td><b>{@linkplain #CELLULAR_AUTOMATON Cellular Automaton RNG}</b></td>
	 * <td><center>32-bit string<br>
	 * <td><center>4 (<code>int</code>)<br>
	 * <td><center>4</td>
	 * <td><center>?</td>
	 * <td><center>4</td>
	 * <td><center>8228</td>
	 * <td><center>Apache License 2.0</td>
	 * <td><center>Experimental</td>
	 * </tr>
	 * </table>
	 * </blockquote>
	 * 
	 * @see <a href="http://en.wikipedia.org/wiki/Cellular_automaton">Wikipedia
	 *      - Cellular automaton</a>
	 * 
	 * @since 2006
	 */
	CELLULAR_AUTOMATON(4) { // one 32-bit integer.

		{ // configure properties
			minlen.set(Randomness.INT_SIZE_BYTES);
			outlen.set(Randomness.INT_SIZE_BYTES);
			period = null; // unknown
			seedlen.set(4);
		}

		@Override
		PseudorandomnessEngine newInstance() {
			return new CellularAutomaton();

		}

	},
	/**
	 * A random number generator based on Cellular Automaton Rule 30.
	 * <p>
	 * This implementation uses an circular array of 192 cells. Each cell is
	 * updated, in parallel, based on the three values, the left neighbor,
	 * itself, and the right neighbor. according to "rule 30" defined by:
	 * </p>
	 * <table border="1" style="text-align: blockquote">
	 * <tr>
	 * <td>111</td>
	 * <td>110</td>
	 * <td>101</td>
	 * <td>100</td>
	 * <td>011</td>
	 * <td>010</td>
	 * <td>001</td>
	 * <td>000</td>
	 * </tr>
	 * <tr>
	 * <td>0</td>
	 * <td>0</td>
	 * <td>0</td>
	 * <td>1</td>
	 * <td>1</td>
	 * <td>1</td>
	 * <td>1</td>
	 * <td>0</td>
	 * </tr>
	 * </table>
	 * <p>
	 * The central or middle cell contains the "random" value.
	 * 
	 * <p>
	 * Using a seed of <code>1L << 32</code> and subsequent calls to
	 * <code>next(1)</code> will produce a sequence of bits equivalent to (in
	 * <i>Mathematica</i>):
	 * </p>
	 * 
	 * <pre>
	 * CellularAutomaton[30,
	 *   ReplacePart[Table[0, {192}], 1, 192/2],
	 *   <i>n</i>,
	 *   {All, {192/2 - 1}}]
	 * </pre>
	 * <p>
	 * The three 64-bit long value define the initial starting conditions and
	 * the bit values are layed out as a bit-string from left to right
	 * 
	 * <pre>
	 * w0-0 w0-1 .... w0-63 w1-0 w1-1 .... w1-63 w2-0 w2-1 ... w2-63
	 * </pre>
	 * 
	 * To get the classical Rule 30 with "black dot" in the middle Use
	 * <code>(0L, 1L << 32, 0L)</code>
	 * <p>
	 * <b>WARNING</b>: Rule 30 has some obvious practical problems. Some initial
	 * conditions will result in loops or terminate (e.g. all 0s). These
	 * problems are <b>not</b> corrected here. This is a "pure" implementation
	 * designed for research (especially since this is quite slow in java)
	 * <p>
	 * <blockquote>
	 * <table border="1" cellpadding="6">
	 * <caption>Table:<b> Properties of Cellular automaton 190 Rule 30
	 * pseudorandom number generator</b> </caption>
	 * <tr>
	 * <th>Name</th>
	 * <th>Precision</th>
	 * <th>Minlen</th>
	 * <th>Outlen</th>
	 * <th>Period</th>
	 * <th>Seedlen</th>
	 * <th>Statelen</th>
	 * <th>License</th>
	 * <th>Category</th>
	 * </tr>
	 * <tr>
	 * <td><b>{@linkplain #CELLULAR_AUTOMATON_192_RULE_30 Celluar Automaton Rule
	 * 30} </b></td>
	 * <td><center>32-bit sting<br>
	 * <td><center>4 (<code>int</code>)<br>
	 * <td><center>4</td>
	 * <td><center>?</td>
	 * <td><center>24 (3 x <code>long</code>'s)</td>
	 * <td><center>24</td>
	 * <td><center>New BSD License</td>
	 * <td><center>Experimental</td>
	 * </tr>
	 * </table>
	 * </blockquote>
	 * 
	 * <ul>
	 * 
	 * @see <a href="http://mathworld.wolfram.com/Rule30.html">MathWorld - Rule
	 *      30</a>
	 * @see <br>
	 *      <a href="http://atlas.wolfram.com/01/01/30/">http://atlas.
	 *      wolfram.com/01/01 /30/</a>
	 * @see <br>
	 *      <a href="http://en.wikipedia.org/wiki/Cellular_automata">Wikipedia -
	 *      Cellular Automata</a>
	 * @see <br>
	 *      <a href="http://www.wolframscience.com/nksonline/page-974b-text"
	 *      >http://www .wolframscience.com/nksonline/page-974b-text</a>
	 * @see <br>
	 *      <a href="http://www.google.com/search?q=US+Patent+4,691,291">US
	 *      Patent 4,691,291</a> (Granted, September 1, 1987, so it should
	 *      expire in 2005)
	 * 
	 * @since 2005
	 */
	CELLULAR_AUTOMATON_192_RULE_30(24 /* 3 x longs */) {

		{ // configure properties
			minlen.set(Randomness.INT_SIZE_BYTES);
			outlen.set(Randomness.INT_SIZE_BYTES);
			period = null; // unknown
			seedlen.set(24);
		}

		@Override
		PseudorandomnessEngine newInstance() {
			return new CellularAutomatonRule30();

		}

	},
	/**
	 * The <i>Bailey-Crandall</i> random number generator based on normal
	 * numbers; this algorithm natively computes <i>random floating-point</i>
	 * numbers instead of the usual random bitstrings.
	 * <p>
	 * This generator is based on properties of the a<sub>2,3</sub>, a
	 * "2-normal" number. <a
	 * href="http://en.wikipedia.org/wiki/Normal_number">Normal numbers</a> have
	 * the interesting property that the binary expansion (infinite) contains
	 * every binary string in exactly same frequency as a
	 * "truly random sequence."
	 * <p>
	 * <blockquote>
	 * <table border="1" cellpadding="6">
	 * <caption>Table:<b> Properties of Bailey-Crandall Pseudoranom Number
	 * Generator</b> </caption>
	 * <tr>
	 * <th>Name</th>
	 * <th>Precision</th>
	 * <th>Minlen</th>
	 * <th>Outlen</th>
	 * <th>Period</th>
	 * <th>Seedlen</th>
	 * <th>Statelen</th>
	 * <th>License</th>
	 * <th>Category</th>
	 * 
	 * </tr>
	 * <tr>
	 * <td><b>{@linkplain #BAILEY_CRANDALL Bailey-Crandall}</b></td>
	 * <td>51-bit floating point <code>double</code> [0,1)</td>
	 * <td>4 bytes
	 * <td><center>8</td>
	 * <td><center>?</td>
	 * <td><center>8</td>
	 * <td><center>56</td>
	 * <td><center>New BSD License</td>
	 * <td><center>Experimental, Floating-point output</td>
	 * </tr>
	 * </table>
	 * </blockquote>
	 * <p>
	 * <b>Algorithm:</b>
	 * </p>
	 * <ol>
	 * <li>Select seed <i>s</i> in the range [ 3<sup>33</sup>, 2<sup>53</sup>]</li>
	 * <li>Compute <i>x</i> = 2<sup><i>s</i> - (3^33)</sup> *
	 * Floor(3<sup>33</sup>/2) mod 3<sup>33</sup></li>
	 * <li>Compute a "random" 64-bit IEEE double value with
	 * <ol>
	 * <li>Compute <i>x</i> = 2<sup>53</sup><i>x</i> mod 3<sup>33</sup></li>
	 * <li>Return <i>x</i>3<sup>-33</sup></li>
	 * </ol>
	 * </li>
	 * </ol>
	 * <p>
	 * In order to do these computations, "double double" (128-bit) arithmetic
	 * is used. The performance could be improved if Java allowed
	 * "fused multiply-add" available on PowerPC and some other microprocessors.
	 * <p>
	 * For any non-floating point values used 32-bit precision random blocks
	 * from the mantissa.
	 * <p>
	 * <b>References</b>:
	 * <ul>
	 * <i> Bailey, David H. and Crandall, Richard "<a
	 * href="http://crd.lbl.gov/~dhbailey/dhbpapers/normal-random.pdf"><i> A
	 * Pseudo-Random Number Generator Based on Normal Numbers</i></a>", 11 Dec
	 * 2004 <br>
	 * Bailey, David H., and Crandall, Richard
	 * "Random Generators and Normal Numbers" Experimental Mathematics, vol 11,
	 * no. 4 (2004) pg. 527-546.</i>
	 * </ul>
	 * 
	 * @see <a href="http://mathworld.wolfram.com/NormalNumber.html">Mathworld -
	 *      Normal Number</a>
	 * 
	 * @since 2004
	 */
	BAILEY_CRANDALL(8) {

		{ // configure properties
			minlen.set(Randomness.INT_SIZE_BYTES);
			outlen.set(Randomness.DOUBLE_SIZE_BYTES);
			period = null; // unknown
			seedlen.set(8);
		}

		@Override
		PseudorandomnessEngine newInstance() {
			return new BaileyCrandall();
		}

	},

	/**
	 * A Java version of George Marsaglia's <a href=
	 * "http://school.anhb.uwa.edu.au/personalpages/kwessen/shared/Marsaglia03.html"
	 * >Complementary Multiply With Carry (CMWC) RNG</a>.
	 * <p>
	 * This is a very fast PRNG with an extremely long period
	 * 2<sup>131104</sup>. It should be used in preference to the other
	 * generators when a very long period is required.
	 * <p>
	 * <blockquote>
	 * <table border="1" cellpadding="6">
	 * <caption>Table:<b> Properties of Complementary Multiply With Carry (CMWC)
	 * RNG</b> </caption>
	 * <tr>
	 * <th>Name</th>
	 * <th>Precision</th>
	 * <th>Minlen</th>
	 * <th>Outlen</th>
	 * <th>Period</th>
	 * <th>Seedlen</th>
	 * <th>Statelen</th>
	 * <th>License</th>
	 * <th>Category</th>
	 * 
	 * </tr>
	 * <tr>
	 * <td><b>{@linkplain #CMWC4096 CMWC4096}</b></td>
	 * <td><center>32-bit string<br>
	 * <td><center>4 (<code>int</code>)<br>
	 * <td><center>4<br>
	 * <td><center>131104</td>
	 * <td><center>16388</td>
	 * <td><center>16392</td>
	 * <td><center>Apache License 2.0</td>
	 * <td><center>Modern, Extra long period</td>
	 * </tr>
	 * 
	 * </table>
	 * </blockquote>
	 * <p>
	 * One potential drawback of this PRNG is that it requires significantly
	 * more seed data than the other PRNGs. It requires just over 16 kilobytes,
	 * which may be a problem if your are obtaining seed data from a slow or
	 * limited entropy source.
	 * 
	 * @see <a
	 *      href="http://en.wikipedia.org/wiki/Multiply-with-carry">Multiply-with-carry</a>
	 * @see <br>
	 *      <a href="http://en.wikipedia.org/wiki/George_Marsaglia">George
	 *      Marsaglia</a>
	 * 
	 * @since 2003
	 */
	CMWC4096(16388) {

		{ // configure properties
			minlen.set(Randomness.INT_SIZE_BYTES);
			outlen.set(Randomness.INT_SIZE_BYTES);
			period = new AtomicInteger(131104);
			seedlen.set(16384);
		}

		@Override
		PseudorandomnessEngine newInstance() {
			return new CMWC4096();
		}
	},

	/**
	 * A <i>64-bit</i> generator using two <a
	 * href="http://en.wikipedia.org/wiki/Xorshift">XOR Shift</a> generators are
	 * combined with an <a
	 * href="http://en.wikipedia.org/wiki/Linear_congruential_generator">LCG</a>
	 * and a <i>multiply with carry</i> (<a
	 * href="http://en.wikipedia.org/wiki/Multiply-with-carry">MWC</a>)
	 * generator provide a good compromise between quality and speed.
	 * <p>
	 * Without going into all the details here, notice the two blocks of three
	 * shifts each, which are the XORShifts; the first line which is the LCG,
	 * similar to the standard {@link Random}, and the line between the two
	 * XORShifts, which is a Multiply-With-Carry generator. Purposed by authors
	 * of <a href=
	 * "http://www.amazon.com/gp/product/0521880688?ie=UTF8&amp;tag=javamex-20&amp;linkCode=as2&amp;camp=1789&amp;creative=9325&amp;creativeASIN=0521880688"
	 * >Numerical Recipes: The Art of Scientific Computing</a> and provide a
	 * good compromise between quality and speed.
	 * <p>
	 * This generator is useful in cases where you need fast, good-quality
	 * randomness but don't need cryptographic randomness, as provided by the <a
	 * href=
	 * "http://www.javamex.com/tutorials/random_numbers/securerandom.shtml"
	 * >Java SecureRandom</a> class. It is not much slower than
	 * <tt>java.util.Random</tt> and provides much better quality randomness and
	 * a much larger period. It is about 20 times faster than
	 * <tt>SecureRandom</tt>. Typical candidates for using this generator would
	 * be games and simulations.
	 * <p>
	 * <blockquote>
	 * <table border="1" cellpadding="6">
	 * <caption>Table:<b> Properties of Combined PRNG</b> </caption>
	 * <tr>
	 * <th>Name</th>
	 * <th>Precision</th>
	 * <th>Minlen</th>
	 * <th>Outlen</th>
	 * <th>Period</th>
	 * <th>Seedlen</th>
	 * <th>Statelen</th>
	 * <th>License</th>
	 * <th>Category</th>
	 * 
	 * </tr>
	 * 
	 * <tr>
	 * <td><b>{@linkplain #COMBINED Combined RNG}</b></td>
	 * <td><center>64-bit string</td>
	 * <td><center>8 (<code>long</code>)</td>
	 * <td><center>8</td>
	 * <td><center>?</td>
	 * <td><center>8</td>
	 * <td><center>24</td>
	 * <td><center>Written by Neil Coffey.<br>
	 * Javamex UK 2010.</td>
	 * <td><center>64-bit precision generation, Games, Simulation</td>
	 * </tr>
	 * </table>
	 * </blockquote>
	 * 
	 * 
	 * @see <a
	 *      href="http://www.javamex.com/tutorials/random_numbers/numerical_recipes.shtml">A
	 *      Java implementation of the Numerical Recipes random number
	 *      generator</a>
	 * 
	 * @since unknown
	 */
	COMBINED(8) {

		{ // configure properties
			minlen.set(Randomness.LONG_SIZE_BYTES);
			outlen.set(Randomness.LONG_SIZE_BYTES);
			period = null; // unknown
			seedlen.set(8);
		}

		@Override
		PseudorandomnessEngine newInstance() {
			return new CombinedRNG();
		}

	}, // one 64-bit long value
	/**
	 * This Linear Congruent Generator is wrapper over
	 * <code>java.util.Random</code> uses a 48-bit seed, which is modified using
	 * a Linear Congruential formula. (See Donald Knuth, <i>The Art of Computer
	 * Programming, Volume 3</i>, Section 3.2.1.).
	 * <p>
	 * LCGs should not be used for applications where high-quality randomness is
	 * critical. For example, it is not suitable for a Monte Carlo simulation
	 * because of the serial correlation. A further problem of LCGs is that the
	 * lower-order bits of the generated sequence have a far shorter period than
	 * the sequence as a whole if m is set to a power of 2. <blockquote>
	 * <table border="1" cellpadding="6">
	 * <caption>Table:<b> Properties of Linear Congruent Generator</b>
	 * </caption>
	 * <tr>
	 * <th>Name</th>
	 * <th>Precision</th>
	 * <th>Minlen</th>
	 * <th>Outlen</th>
	 * <th>Period</th>
	 * <th>Seedlen</th>
	 * <th>Statelen</th>
	 * <th>License</th>
	 * <th>Category</th>
	 * 
	 * </tr>
	 * 
	 * <tr>
	 * <td><b>{@linkplain #LCG Linear Congruent Generator},<br>
	 * {@link #UTIL_RANDOM java.util.Random},<br>
	 * {@link #NATIVE} (system default)</b></td>
	 * <td><center>48-bit string<br>
	 * <td><center>4 (<code>int</code>)<br>
	 * <td><center>4</td>
	 * <td><center>48</td>
	 * <td><center>8</td>
	 * <td><center>8</td>
	 * <td><center>GPL</td>
	 * <td><center>Classic</td>
	 * </tr>
	 * </table>
	 * </blockquote>
	 * <p>
	 * 
	 * @see <a
	 *      href="http://en.wikipedia.org/wiki/Linear_congruential_generator">Wikipedia
	 *      - Linear congruential generator </a>
	 * @see <br>
	 *      <a href=
	 *      "http://www.javamex.com/tutorials/random_numbers/java_util_random.shtml"
	 *      >Using <code>java.util.Random</code></a>
	 * 
	 * @since 1996
	 */
	LCG(8) {

		{ // configure properties
			minlen.set(Randomness.INT_SIZE_BYTES);
			outlen.set(Randomness.INT_SIZE_BYTES);
			period = new AtomicInteger(48);
			seedlen.set(8);
		}

		@Override
		PseudorandomnessEngine newInstance() {
			return new LCG2();
		}

		@Override
		public Pseudorandomness shared() {
			return new LCG2.Shared();
		}

	}, // one 64-bit long value.
	/**
	 * <p>
	 * Exceptionally high-quality, fast pseudoranom number generator based on
	 * the <a href="http://www.math.sci.hiroshima-u.ac.jp/~m-mat/MT/emt.html"
	 * target="_top">Mersenne Twister</a> algorithm with a good statistical
	 * properties developed by Makoto Matsumoto and Takuji Nishimura.
	 * <p>
	 * In 1997 Makoto Matsumoto and Takuji Nishimura published the Mersenne
	 * Twister algorithm, which avoided many of the problems with earlier
	 * generators. They presented two versions, MT11213 and MT19937, with
	 * periods of 2^11213-1 and 2^19937-1 (approximately 10^6001), which
	 * represents far more computation than is likely possible in the lifetime
	 * of the entire universe. MT19937 uses an internal state of 624 ints, or
	 * 19968 bits, which is about expected for the huge period.
	 * <p>
	 * It is faster than the {@link #LCG LCG}, is equidistributed in up to 623
	 * dimensions, and has become the main RNG used in statistical simulations.
	 * The speed comes from only updating a small part of the state for each
	 * random number generated, and moving through the state over multiple
	 * calls. Mersenne Twister is a <i>Twisted Generalized Feedback Shift
	 * register</i> (TGFSR). It is <b>not</b> cryptographically secure:
	 * observing 624 sequential outputs allows one to determine the internal
	 * state, and then predict the remaining sequence (<a href=
	 * "http://jazzy.id.au/default/2010/09/22/cracking_random_number_generators_part_3.html"
	 * >link1</a>, <a href=
	 * "http://jazzy.id.au/default/2010/09/25/cracking_random_number_generators_part_4.html"
	 * >link2</a>). Mersenne Twister has some flaws, covered in the
	 * {@link #WELL19937c} and {@link #SFMT} algorithms below.
	 * <p>
	 * This is the best PRNG for most experiments. It passes the full DIEHARD
	 * suite. The MersenneTwister generator uses a 624 elements integer array,
	 * so it consumes less than 2.5 kilobytes.
	 * <p>
	 * <blockquote>
	 * <table border="1" cellpadding="6">
	 * <caption>Table:<b> Properties of Mersenne Twister Generator</b>
	 * </caption>
	 * <tr>
	 * <th>Name</th>
	 * <th>Precision</th>
	 * <th>Minlen</th>
	 * <th>Outlen</th>
	 * <th>Period</th>
	 * <th>Seedlen</th>
	 * <th>Statelen</th>
	 * <th>License</th>
	 * <th>Category</th>
	 * </tr>
	 * 
	 * <tr>
	 * <td><b>{@linkplain #MT Mersenne Twister}</b></td>
	 * <td><center>19937-bit array<br>
	 * <td><center>4 (<code>int</code>)<br>
	 * <td><center>2496 <br>
	 * (uses a 624 elements integer array)</td>
	 * <td><center>19937</td>
	 * <td><center>16</td>
	 * <td><center>2500</td>
	 * <td><center>Apache License 2.0.</td>
	 * <td><center>Professional, Simulation, Fast Generator, Block Output.</td>
	 * </tr>
	 * </table>
	 * </blockquote>
	 * <p>
	 * <b>Reference. </b>
	 * <ul>
	 * <i> Makato Matsumoto and Takuji Nishimura, "Mersenne Twister: A
	 * 623-Dimensionally Equidistributed Uniform Pseudo-Random Number
	 * Generator", <i>ACM Transactions on Modeling and. Computer Simulation,</i>
	 * Vol. 8, No. 1, January 1998, pp 3--30.</i>
	 * </ul>
	 * 
	 * @see <a
	 *      href="http://www.math.sci.hiroshima-u.ac.jp/~m-mat/MT/emt.html">Mersenne
	 *      Twister Home Page</a>
	 * @see <br>
	 *      <a href="http://en.wikipedia.org/wiki/Mersenne_twister">Wikipedia -
	 *      Mersenne twister</a>
	 * 
	 * @since 1997
	 * 
	 */
	MT(16) { // The actual seed size isn't that
				// important, but it should be a multiple of 4.

		{ // configure properties
			minlen.set(Randomness.INT_SIZE_BYTES);
			outlen.set(624 * Randomness.INT_SIZE_BYTES);
			// MT with different periods acquire different block sizes.
			period = new AtomicInteger(19937);
			seedlen.set(16);
		}

		@Override
		PseudorandomnessEngine newInstance() {
			return new MT();
		}

		@Override
		public final MT.Shared shared() {

			MT mt = new MT();

			// shared wrapper around MT
			MT.Shared shared = mt.new Shared();
			return shared;
		}
	},

	/**
	 * <p>
	 * This is a <i>64-bit</i> version of Mersenne Twister pseudorandom number
	 * generator with the same statistical properties as original 32-bit version
	 * but is implemented use 64-bit registers (<code>long</code>) and produces
	 * different output; Mersenne Twister 64 is unique in that it natively
	 * generates 64-bit of randomness per cycle.
	 * <p>
	 * This is a very fast random number generator with good statistical
	 * properties (it passes the full DIEHARD suite). This is the best PRNG for
	 * most experiments if needed 64-bit values. The output has 64 bits of
	 * precision. The output of this version of Mersenne Twister is differs from
	 * default 32-bit version of {@linkplain PRNG#MERSENNE_TWISTER Mersenne
	 * twister} generator.
	 * <p>
	 * <blockquote>
	 * <table border="1" cellpadding="6">
	 * <caption>Table:<b> Properties of Mersenne Twisted 64-bit version</b>
	 * </caption>
	 * <tr>
	 * <th>Name</th>
	 * <th>Precision</th>
	 * <th>Minlen</th>
	 * <th>Outlen</th>
	 * <th>Period</th>
	 * <th>Seedlen</th>
	 * <th>Statelen</th>
	 * <th>License</th>
	 * <th>Category</th>
	 * 
	 * </tr>
	 * <tr>
	 * <td><b>{@linkplain #MT64 Mersenne Twister 64 bit}</b></td>
	 * <td><center>19937-bit array</td>
	 * <td><center>8 (<code>long</code>)</td>
	 * <td><center>2496 <br>
	 * (uses a 312 elements <code>long</code>'s array)</td>
	 * <td><center>19937</td>
	 * <td><center>32</td>
	 * <td><center>2500</td>
	 * <td><center>Apache License 2.0.</td>
	 * <td><center>64-bit precision output, Professional, Simulation, Fast
	 * Generator, Block Output.</td>
	 * 
	 * </tr>
	 * 
	 * 
	 * </table>
	 * </blockquote>
	 * <p>
	 * <b>References</b>:
	 * <ul>
	 * <i>"Tables of 64-bit Mersenne Twisters" ACM Transactions on Modeling and
	 * Computer Simulation 10. (2000) 348--357. M. Matsumoto and T.
	 * Nishimura</i>,<br>
	 * <i>"Mersenne Twister: a 623-dimensionally equidistributed uniform
	 * pseudorandom number generator" ACM Transactions on Modeling and Computer
	 * Simulation 8. (Jan. 1998) 3--30</i>.
	 * </ul>
	 * 
	 * @see PRNG#COMBINED Combined 64-bit output PRNG
	 * @see <br>
	 *      <a
	 *      href="http://www.math.sci.hiroshima-u.ac.jp/~m-mat/MT/emt64.html">
	 *      Mersenne Twister 64-bit version </a>
	 * @see <br>
	 *      This is mostly a straight port of the <a href=
	 *      "http://www.math.sci.hiroshima-u.ac.jp/~m-mat/MT/VERSIONS/C-LANG/mt19937-64.c"
	 *      > C-code (mt19937-64.c)</a>
	 * @see <br>
	 *      <a href="http://en.wikipedia.org/wiki/Mersenne_twister">Wikipedia -
	 *      Mersenne Twister</a>
	 * 
	 * @since 2000
	 * 
	 */
	MT64(32) { // The actual seed size isn't
				// that important, but it should be a multiple of 8.

		{ // configure properties
			minlen.set(Randomness.LONG_SIZE_BYTES);
			outlen.set(312 * Randomness.LONG_SIZE_BYTES);
			// MT with different periods acquire different block sizes.
			period = new AtomicInteger(19937);
			seedlen.set(32);
		}

		@Override
		PseudorandomnessEngine newInstance() {
			return new MT64();
		}

		@Override
		public final MT64.Shared shared() {

			MT64 mt = new MT64();

			// shared wrapper around MT64
			MT64.Shared shared = mt.new Shared();
			return shared;

		}
	},
	/**
	 * SFMT algorithm implements the <a
	 * href="http://www.math.sci.hiroshima-u.ac.jp/~m-mat/MT/SFMT/index.html"
	 * >SIMD-oriented Fast Mersenne Twister</a> version 1.3 by Mutsuo Saito
	 * (Hiroshima University) and Makoto Matsumoto (Hiroshima University).
	 * <p>
	 * SFMT is a new variant of Mersenne Twister (MT) introduced in 2006. SFMT
	 * is a Linear Feedbacked Shift Register (LFSR) generator that generates a
	 * 128-bit pseudorandom integer at one step. SFMT is designed with recent
	 * parallelism of modern CPUs, such as multi-stage pipelining and SIMD (e.g.
	 * 128-bit integer) instructions. It supports 32-bit and 64-bit integers, as
	 * well as double precision floating point as output. SFMT is much faster
	 * than {@linkplain PRNG#MT Mersenne Twister}, in most platforms. Not only
	 * the speed, but also the dimensions of equidistributions at v-bit
	 * precision are improved. In addition, recovery from 0-excess initial state
	 * is much faster.
	 * <p>
	 * This adaptation supports only the period 2<sup>19937</sup> &minus; 1; the
	 * original supports some longer and shorter periods: 2<sup>607</sup>
	 * &minus;1, 2<sup>1279</sup>&minus;1, ..., 2<sup>132049</sup>&minus;1,
	 * 2<sup>216091</sup>&minus;1.
	 * <p>
	 * <blockquote>
	 * <table border="1" cellpadding="6">
	 * <caption>Table:<b> Properties of SIMD-oriented Fast Mersenne Twister
	 * Generator</b> </caption>
	 * <tr>
	 * <th>Name</th>
	 * <th>Precision</th>
	 * <th>Minlen</th>
	 * <th>Outlen</th>
	 * <th>Period</th>
	 * <th>Seedlen</th>
	 * <th>Statelen</th>
	 * <th>License</th>
	 * <th>Category</th>
	 * 
	 * </tr>
	 * <td><b>{@linkplain #SFMT SIMD-oriented Fast Mersenne Twister}</b></td>
	 * <td><center>19937-bit array<br>
	 * <td><center>4 (<code>int</code>)<br>
	 * <td><center>2496 <br>
	 * (uses a 624 elements integer array)</td>
	 * <td><center>19937</td>
	 * <td><center>32</td>
	 * <td><center>2500</td>
	 * <td><center>modified BSD License</td>
	 * <td><center>Simulation, Best equidistribution properties, Extra-Fast
	 * Generator, Block Output</td>
	 * </tr>
	 * 
	 * </table>
	 * </blockquote>
	 * <p>
	 * 
	 * @see <a href=
	 *      "http://www.math.sci.hiroshima-u.ac.jp/%7Em-mat/MT/SFMT/M062821.pdf"
	 *      >Master's Thesis of Mutsuo Saito for detail</a>
	 * @see <br>
	 *      <a
	 *      href="http://www.math.sci.hiroshima-u.ac.jp/~m-mat/MT/SFMT/index.html"
	 *      >SIMD-oriented Fast Mersenne Twister (SFMT) web page</a>
	 * @see <br>
	 *      <a
	 *      href="http://en.wikipedia.org/wiki/Mersenne_twister#SFMT">Wikipedia
	 *      - SFMT</a>
	 * @see <br>
	 *      <a
	 *      href="http://en.wikipedia.org/wiki/SSE2#CPUs_supporting_SSE2">Wikipedia
	 *      SSE2:CPUs supporting SSE2</a>
	 * 
	 * @since 2007
	 */
	SFMT(16) { // The actual seed size isn't that important, but it should be a
				// multiple of 4.

		{ // configure properties
			minlen.set(Randomness.INT_SIZE_BYTES);
			outlen.set(624 * Randomness.INT_SIZE_BYTES);
			// MT with different periods acquire different block sizes.
			period = new AtomicInteger(19937);
			seedlen.set(16);
		}

		@Override
		PseudorandomnessEngine newInstance() {
			return new SFMT();
		}

		@Override
		public final SFMT.Shared shared() {
			SFMT mt = new SFMT();

			// shared wrapper around MT64
			SFMT.Shared shared = mt.new Shared();
			return shared;

		}
	},
	/**
	 * <i>NOT IMPLEMENTED YET, WORK IN PROGRESS: </i>An adaptation of <a href=
	 * "http://www.math.sci.hiroshima-u.ac.jp/~m-mat/MT/SFMT/index.html#dSFMT" >
	 * Double precision SIMD-oriented Fast Mersenne Twister</a> (dSFMT) version
	 * 2.1 by Mutsuo Saito (Hiroshima University) and Makoto Matsumoto
	 * (Hiroshima University).
	 * <p>
	 * The purpose of dSFMT is to speed up the generation by avoiding the
	 * expensive conversion of integer to double (floating point). dSFMT
	 * directly generates double precision floating point pseudorandom numbers
	 * which have the IEEE Standard for Binary Floating-Point Arithmetic
	 * (ANSI/IEEE Std 754-1985) format. dSFMT is only available on the CPUs
	 * which use IEEE 754 format double precision floating point numbers. (Java
	 * use it).
	 * 
	 * <blockquote>
	 * <table border="1" cellpadding="6">
	 * <caption>Table:<b> Properties of Double precision SIMD-oriented Fast
	 * Mersenne Twister</b> </caption>
	 * <tr>
	 * <th>Name</th>
	 * <th>Precision</th>
	 * <th>Minlen</th>
	 * <th>Outlen</th>
	 * <th>Period</th>
	 * <th>Seedlen</th>
	 * <th>Statelen</th>
	 * <th>License</th>
	 * <th>Category</th>
	 * </tr>
	 * <tr>
	 * <td><b> {@linkplain #dSFMT2 dSFMT2} </b></td>
	 * <td><center>64-bit floating point<br>
	 * <td><center>8 (<code>int</code>)<br>
	 * <td><center>4</td>
	 * <td><center><b>2496 </b></td>
	 * <td><center>16</td>
	 * <td><center>2500</td>
	 * <td><center>Apache License Version 2.0</td>
	 * <td><center>floating-point output</td>
	 * </tr>
	 * </table>
	 * </blockquote>
	 * <p>
	 * dSFMT doesn't support integer outputs. dSFMT supports the output of
	 * double precision floating point pseudorandom numbers which distribute in
	 * the range of [1, 2), [0, 1), (0, 1] and (0, 1). And it also supports the
	 * various periods form 2<sup>607</sup>-1 to 2<sup>132049</sup>-1. (dSFMT
	 * ver. 2.1 supports the periods from 2<sup>521</sup>-1 to
	 * 2<sup>216091</sup>-1.)
	 * </p>
	 * <p>
	 * 
	 * @see <a
	 *      href="http://www.math.sci.hiroshima-u.ac.jp/~m-mat/MT/SFMT/dSFMT-slide-e.pdf">Slides</a>
	 *      was used for the talk at MCQMC 2008
	 * 
	 * @since 2009
	 */
	dSFMT2(16) {

		{ // configure properties
			minlen.set(Randomness.DOUBLE_SIZE_BYTES);
			outlen.set(312 * Randomness.DOUBLE_SIZE_BYTES);
			// MT with different periods acquire different block sizes.
			period = new AtomicInteger(19937);
			seedlen.set(16);
		}

		@Override
		PseudorandomnessEngine newInstance() {
			return new dSFMT2();
		}

	},
	/**
	 * <i>Well Equidistributed Long-period Linear</i> (WELL) is in a 32-bit
	 * pseudorandom rumber generator with period 2<sup>512</sup> proposed by
	 * Fran&ccedil;ois Panneton, Pierre L'Ecuyer and Makoto Matsumoto.
	 * <p>
	 * Matsumoto (co-creator of the Mersenne Twister), L’Ecuyer (a major RNG
	 * researcher), and Panneton introduced another class of TGFSR PRNGs in
	 * 2006. These algorithms produce numbers with better equidistribution than
	 * Mersenne Twister and improve upon “bit-mixing” properties. They are fast,
	 * come in many sizes, and produce higher quality random numbers. The only
	 * downside is that WELL are slightly slower than MT19937, but not much. The
	 * upside is the numbers are considered to be higher quality, and the code
	 * is significantly simpler. The WELL generators are better to escape
	 * zeroland as explained by the WELL generators creators.
	 * <p>
	 * WELL period sizes are presented for period 2^n for n = <b>
	 * {@linkplain #WELL512a 512}</b>, 521, 607, 800, <b>
	 * {@linkplain #WELL1024a 1024} </b>,<b>{@linkplain #WELL19937c 19937}</b> ,
	 * 21701, 23209, and <b>{@linkplain #WELL44497b 44497}</b>, with
	 * corresponding state sizes. This allows a user to trade period length for
	 * state size. All run at similar speed. 2^512 is about 10^154, and it is
	 * unlikely any video game will ever need that many random numbers, since it
	 * is far larger then the number of particles in the universe. <blockquote>
	 * <table border="1" cellpadding="6">
	 * <caption>Table:<b> Properties of WELL512a Generator</b> </caption>
	 * <tr>
	 * <th>Name</th>
	 * <th>Precision</th>
	 * <th>Minlen</th>
	 * <th>Outlen</th>
	 * <th>Period</th>
	 * <th>Seedlen</th>
	 * <th>Statelen</th>
	 * <th>License</th>
	 * <th>Category</th>
	 * </tr>
	 * <tr>
	 * <td><b> {@linkplain #WELL512a WELL512a} </b></td>
	 * <td><center>32-bit string<br>
	 * <td><center>4 (<code>int</code>)<br>
	 * <td><center>4</td>
	 * <td><center><b>512</b></td>
	 * <td><center>64</td>
	 * <td><center>24</td>
	 * <td><center>Apache License Version 2.0</td>
	 * <td><center>Professional, Simulation, Fast Generator, Best
	 * equidistribution properties</td>
	 * </tr>
	 * </table>
	 * </blockquote>
	 * <p>
	 * <b>Reference:</b >
	 * <ul>
	 * <i>Fran&ccedil;ois Panneton, Pierre L'Ecuyer and Makoto Matsumoto <a
	 * href="http://www.iro.umontreal.ca/~lecuyer/myftp/papers/wellrng.pdf"
	 * >Improved Long-Period Generators Based on Linear Recurrences Modulo 2</a>
	 * ACM Transactions on Mathematical Software, 32, 1 (2006). <a href=
	 * "http://www.iro.umontreal.ca/~lecuyer/myftp/papers/wellrng-errata.txt"
	 * >The errata for the paper</a></i>
	 * </ul>
	 * 
	 * @since 2006
	 * 
	 * @see <a href=
	 *      "http://en.wikipedia.org/wiki/Well_Equidistributed_Long-period_Linear">
	 *      Wikipedia - WELL</a>
	 * 
	 * @see <br>
	 *      <a href="http://www.iro.umontreal.ca/~panneton/WELLRNG.html">WELL
	 *      Random number generator</a>
	 * 
	 * @see <br>
	 *      <a href="http://commons.apache.org/math/">Apache commons-math</a>
	 *      WELL implementation
	 * 
	 * @see <br>
	 *      <a href="http://www.iro.umontreal.ca/~simardr/ssj/indexe.html">SSJ:
	 *      Stochastic Simulation in Java</a> (Contains several WELL
	 *      implementations)
	 */
	WELL512a(64) {
		{
			minlen.set(Randomness.INT_SIZE_BYTES);
			outlen.set(Randomness.INT_SIZE_BYTES);
			period = new AtomicInteger(512);
			seedlen.set(64);
		}

		@Override
		WELL512a newInstance() {
			return new WELL512a();
		}
	},

	/**
	 * WELL1024a is in a 32-bit <i>Well Equidistributed Long-period Linear</i>
	 * pseudorandom rumber generator with period 2<sup>1024</sup> and better
	 * equidistribution than {@linkplain #MT Mersenne Twister} algorithm but a
	 * slight higher cost of time proposed by Fran&ccedil;ois Panneton, Pierre
	 * L'Ecuyer and Makoto Matsumoto.
	 * <p>
	 * WELL algorithms produce numbers with better equidistribution than
	 * Mersenne Twister and improve upon “bit-mixing” properties. They are fast,
	 * come in many sizes, and produce higher quality random numbers. The only
	 * downside is that WELL are slightly slower than MT19937, but not much. The
	 * upside is the numbers are considered to be higher quality, and the code
	 * is significantly simpler. If initialization array contains many zero
	 * bits, MersenneTwister may take a very long time (several hundreds of
	 * thousands of iterations to reach a steady state with a balanced number of
	 * zero and one in its bits pool). So the WELL generators are better to
	 * escape zeroland as explained by the WELL generators creators.
	 * <p>
	 * WELL period sizes are presented for period 2^n for n = <b>
	 * {@linkplain #WELL512a 512}</b>, 521, 607, 800, <b>
	 * {@linkplain #WELL1024a 1024} </b>,<b>{@linkplain #WELL19937c 19937}</b> ,
	 * 21701, 23209, and <b>{@linkplain #WELL44497b 44497}</b>, with
	 * corresponding state sizes. The larger periods ones aren’t really needed
	 * except for computation like weather modeling or earth simulations.
	 * <p>
	 * WELL1024a , WELL19937c and WELL44497b are maximally equidistributed for
	 * blocks size up to 32 bits (they should behave correctly also for double
	 * based on more than 32 bits blocks, but equidistribution is not proven at
	 * these blocks sizes). <blockquote>
	 * <table border="1" cellpadding="6">
	 * <caption>Table:<b> Properties of WELL1024a Generator</b> </caption>
	 * <tr>
	 * <th>Name</th>
	 * <th>Precision</th>
	 * <th>Minlen</th>
	 * <th>Outlen</th>
	 * <th>Period</th>
	 * <th>Seedlen</th>
	 * <th>Statelen</th>
	 * <th>License</th>
	 * <th>Category</th>
	 * </tr>
	 * <tr>
	 * <td><b>{@linkplain #WELL1024a WELL1024a}</b></td>
	 * <td><center>32-bit string<br>
	 * <td><center>4 (<code>int</code>)<br>
	 * <td><center>4</td>
	 * <td><center><b>1024</b></td>
	 * <td><center>128</td>
	 * <td><center>768</td>
	 * <td><center>Apache License Version 2.0</td>
	 * <td><center>Professional, Simulation, Fast Generator, Best
	 * equidistribution properties</td>
	 * </tr>
	 * </table>
	 * </blockquote>
	 * <p>
	 * <b>Reference:</b >
	 * <ul>
	 * <i>Fran&ccedil;ois Panneton, Pierre L'Ecuyer and Makoto Matsumoto <a
	 * href="http://www.iro.umontreal.ca/~lecuyer/myftp/papers/wellrng.pdf"
	 * >Improved Long-Period Generators Based on Linear Recurrences Modulo 2</a>
	 * ACM Transactions on Mathematical Software, 32, 1 (2006). <a href=
	 * "http://www.iro.umontreal.ca/~lecuyer/myftp/papers/wellrng-errata.txt"
	 * >The errata for the paper</a></i>
	 * </ul>
	 * 
	 * @since 2006
	 * 
	 * @see <a href=
	 *      "http://en.wikipedia.org/wiki/Well_Equidistributed_Long-period_Linear">
	 *      Wikipedia - WELL</a>
	 * 
	 * @see <br>
	 *      <a href="http://www.iro.umontreal.ca/~panneton/WELLRNG.html">WELL
	 *      Random number generator</a>
	 * 
	 * @see <br>
	 *      <a href="http://commons.apache.org/math/">Apache commons-math</a>
	 *      WELL implementation
	 * 
	 * @see <br>
	 *      <a href="http://www.iro.umontreal.ca/~simardr/ssj/indexe.html">SSJ:
	 *      Stochastic Simulation in Java</a> (Contains several WELL
	 *      implementations)
	 */
	WELL1024a(128) {

		{
			minlen.set(Randomness.INT_SIZE_BYTES);
			outlen.set(Randomness.INT_SIZE_BYTES);
			seedlen.set(128);

			period = new AtomicInteger(1024);
		}

		@Override
		WELL1024a newInstance() {
			return new WELL1024a();
		}
	},
	/**
	 * WELL19937c is in a 32-bit <i>Well Equidistributed Long-period Linear</i>
	 * pseudorandom rumber generator with period 2<sup>19937</sup> and better
	 * equidistribution than {@linkplain #MT Mersenne Twister} algorithm but a
	 * slight higher cost of time proposed by Fran&ccedil;ois Panneton, Pierre
	 * L'Ecuyer and Makoto Matsumoto.
	 * <p>
	 * WELL algorithms produce numbers with better equidistribution than
	 * Mersenne Twister and improve upon “bit-mixing” properties. They are fast,
	 * come in many sizes, and produce higher quality random numbers. The only
	 * downside is that WELL are slightly slower than MT19937, but not much. The
	 * upside is the numbers are considered to be higher quality, and the code
	 * is significantly simpler. If initialization array contains many zero
	 * bits, MersenneTwister may take a very long time (several hundreds of
	 * thousands of iterations to reach a steady state with a balanced number of
	 * zero and one in its bits pool). So the WELL generators are better to
	 * escape zeroland as explained by the WELL generators creators.
	 * <p>
	 * WELL period sizes are presented for period 2^n for n = <b>
	 * {@linkplain #WELL512a 512}</b>, 521, 607, 800, <b>
	 * {@linkplain #WELL1024a 1024} </b>,<b>{@linkplain #WELL19937c 19937}</b> ,
	 * 21701, 23209, and <b>{@linkplain #WELL44497b 44497}</b>, with
	 * corresponding state sizes. The larger periods ones aren’t really needed
	 * except for computation like weather modeling or earth simulations.
	 * <p>
	 * <b>Note:</b> The WELL generators use 6 integer arrays with a size equal
	 * to the pool size, so the WELL19937 generator uses about 15 kilobytes.
	 * This may be important if a very large number of generator instances were
	 * used at the same time.
	 * <p>
	 * WELL19937c and are maximally equidistributed for blocks size up to 32
	 * bits (they should behave correctly also for double based on more than 32
	 * bits blocks, but equidistribution is not proven at these blocks sizes).
	 * <blockquote>
	 * <table border="1" cellpadding="6">
	 * <caption>Table:<b> Properties of WELL19937c Generator</b> </caption>
	 * <tr>
	 * <th>Name</th>
	 * <th>Precision</th>
	 * <th>Minlen</th>
	 * <th>Outlen</th>
	 * <th>Period</th>
	 * <th>Seedlen</th>
	 * <th>Statelen</th>
	 * <th>License</th>
	 * <th>Category</th>
	 * </tr>
	 * <tr>
	 * <td><b>{@linkplain #WELL19937c}</b></td>
	 * <td><center>32-bit string<br>
	 * <td><center>4 (<code>int</code>)<br>
	 * <td><center>4</td>
	 * <td><center><b> 19937</b></td>
	 * <td><center>2496</td>
	 * <td><center><b>15k</b></td>
	 * <td><center>Apache License Version 2.0</td>
	 * <td><center>Professional, Simulation, Modeling, Fast Generator, Best
	 * equidistribution properties</td>
	 * </tr>
	 * </table>
	 * </blockquote>
	 * <p>
	 * <b>Reference:</b >
	 * <ul>
	 * <i>Fran&ccedil;ois Panneton, Pierre L'Ecuyer and Makoto Matsumoto <a
	 * href="http://www.iro.umontreal.ca/~lecuyer/myftp/papers/wellrng.pdf"
	 * >Improved Long-Period Generators Based on Linear Recurrences Modulo 2</a>
	 * ACM Transactions on Mathematical Software, 32, 1 (2006). <a href=
	 * "http://www.iro.umontreal.ca/~lecuyer/myftp/papers/wellrng-errata.txt"
	 * >The errata for the paper</a></i>
	 * </ul>
	 * 
	 * @since 2006
	 * 
	 * @see <a href=
	 *      "http://en.wikipedia.org/wiki/Well_Equidistributed_Long-period_Linear">
	 *      Wikipedia - WELL</a>
	 * 
	 * @see <br>
	 *      <a href="http://www.iro.umontreal.ca/~panneton/WELLRNG.html">WELL
	 *      Random number generator</a>
	 * 
	 * @see <br>
	 *      <a href="http://commons.apache.org/math/">Apache commons-math</a>
	 *      WELL implementation
	 * 
	 * @see <br>
	 *      <a href="http://www.iro.umontreal.ca/~simardr/ssj/indexe.html">SSJ:
	 *      Stochastic Simulation in Java</a>
	 */
	WELL19937c(2496) {
		{
			minlen.set(Randomness.INT_SIZE_BYTES);
			outlen.set(Randomness.INT_SIZE_BYTES);
			period = new AtomicInteger(19937);
			seedlen.set(2496);
		}

		@Override
		WELL19937c newInstance() {
			return new WELL19937c();
		}
	},
	/**
	 * WELL44497b is in a 32-bit <i>Well Equidistributed Long-period Linear</i>
	 * pseudorandom rumber generator with period 2<sup>44497</sup> and better
	 * equidistribution than {@linkplain #MT Mersenne Twister} algorithm but a
	 * slight higher cost of time proposed by Fran&ccedil;ois Panneton, Pierre
	 * L'Ecuyer and Makoto Matsumoto.
	 * <p>
	 * WELL algorithms produce numbers with better equidistribution than
	 * Mersenne Twister and improve upon “bit-mixing” properties. They are fast,
	 * come in many sizes, and produce higher quality random numbers. The only
	 * downside is that WELL are slightly slower than MT19937, but not much. The
	 * upside is the numbers are considered to be higher quality, and the code
	 * is significantly simpler. If initialization array contains many zero
	 * bits, MersenneTwister may take a very long time (several hundreds of
	 * thousands of iterations to reach a steady state with a balanced number of
	 * zero and one in its bits pool). So the WELL generators are better to
	 * escape zeroland as explained by the WELL generators creators.
	 * <p>
	 * WELL period sizes are presented for period 2^n for n = <b>
	 * {@linkplain #WELL512a 512}</b>, 521, 607, 800, <b>
	 * {@linkplain #WELL1024a 1024} </b>,<b>{@linkplain #WELL19937c 19937}</b> ,
	 * 21701, 23209, and <b>{@linkplain #WELL44497b 44497}</b>, with
	 * corresponding state sizes.
	 * <p>
	 * <b>Note</b> that WELL generators use 6 integer arrays with a size equal
	 * to the pool size, so the the WELL44497b generator uses about 33
	 * kilobytes. This may be important if a very large number of generator
	 * instances were used at the same time.
	 * <p>
	 * WELL44497b are maximally equidistributed for blocks size up to 32 bits
	 * (they should behave correctly also for double based on more than 32 bits
	 * blocks, but equidistribution is not proven at these blocks sizes).
	 * <blockquote>
	 * <table border="1" cellpadding="6">
	 * <caption>Table:<b> Properties of WELL44497b Generator</b> </caption>
	 * <tr>
	 * <th>Name</th>
	 * <th>Precision</th>
	 * <th>Minlen</th>
	 * <th>Outlen</th>
	 * <th>Period</th>
	 * <th>Seedlen</th>
	 * <th>Statelen</th>
	 * <th>License</th>
	 * <th>Category</th>
	 * </tr>
	 * <tr>
	 * <td><b>{@linkplain #WELL44497b}</b></td>
	 * <td><center>32-bit string<br>
	 * <td><center>4 (<code>int</code>)<br>
	 * <td><center>4</td>
	 * <td><center><b> 44497</b></td>
	 * <td><center>5564</td>
	 * <td><center><b>33k</b></td>
	 * <td><center>Apache License Version 2.0</td>
	 * <td><center>Professional, Simulation, Modeing, Fast Generator, Best
	 * equidistribution properties</td>
	 * </tr>
	 * </table>
	 * </blockquote>
	 * <p>
	 * <b>Reference:</b >
	 * <ul>
	 * <i>Fran&ccedil;ois Panneton, Pierre L'Ecuyer and Makoto Matsumoto <a
	 * href="http://www.iro.umontreal.ca/~lecuyer/myftp/papers/wellrng.pdf"
	 * >Improved Long-Period Generators Based on Linear Recurrences Modulo 2</a>
	 * ACM Transactions on Mathematical Software, 32, 1 (2006). <a href=
	 * "http://www.iro.umontreal.ca/~lecuyer/myftp/papers/wellrng-errata.txt"
	 * >The errata for the paper</a></i>
	 * </ul>
	 * 
	 * @since 2006
	 * 
	 * @see <a href=
	 *      "http://en.wikipedia.org/wiki/Well_Equidistributed_Long-period_Linear">
	 *      Wikipedia - WELL</a>
	 * 
	 * @see <br>
	 *      <a href="http://www.iro.umontreal.ca/~panneton/WELLRNG.html">WELL
	 *      Random number generator</a>
	 * 
	 * @see <br>
	 *      <a href="http://commons.apache.org/math/">Apache commons-math</a>
	 *      WELL implementation
	 * 
	 * @see <br>
	 *      <a href="http://www.iro.umontreal.ca/~simardr/ssj/indexe.html">SSJ:
	 *      Stochastic Simulation in Java</a>
	 */
	WELL44497b(5564) {
		{
			minlen.set(Randomness.INT_SIZE_BYTES);
			outlen.set(Randomness.INT_SIZE_BYTES);
			period = new AtomicInteger(44497);
			seedlen.set(5564);
		}

		@Override
		WELL44497b newInstance() {
			return new WELL44497b();
		}
	},

	/**
	 * Very fast PRNG using XOR Shift purposed by George Marsaglia.
	 * <p>
	 * This PRNG has a period of about 2<sup>160</sup>, which is not as long as
	 * the {@linklain #MT Mersenne twister} but it is faster.
	 * <p>
	 * <blockquote>
	 * <table border="1" cellpadding="6">
	 * <caption>Table:<b> Properties of SIMD-oriented Fast Mersenne Twister
	 * Generator</b> </caption>
	 * <tr>
	 * <th>Name</th>
	 * <th>Precision</th>
	 * <th>Minlen</th>
	 * <th>Outlen</th>
	 * <th>Period</th>
	 * <th>Seedlen</th>
	 * <th>Statelen</th>
	 * <th>License</th>
	 * <th>Category</th>
	 * <tr>
	 * <td><b>{@linkplain #XOR_SHIFT XOR Shift}</b></td>
	 * <td><center>32-bit string<br>
	 * <td><center>4 (<code>int</code>)<br>
	 * <td><center>4</td>
	 * <td><center>160</td>
	 * <td><center>20</td>
	 * <td><center>20</td>
	 * <td><center>Apache License Version 2.0</td>
	 * <td><center>Modern, Fast</td>
	 * 
	 * </tr>
	 * </table>
	 * </blockquote>
	 * <p>
	 * 
	 * @see <a href=
	 *      "http://school.anhb.uwa.edu.au/personalpages/kwessen/shared/Marsaglia03.html"
	 *      >Good random number generator from George Marsaglia</a>
	 * @see <a
	 *      href="http://www.javamex.com/tutorials/random_numbers/xorshift.shtml">XORShift
	 *      random number generators</a>
	 * @see <a href="http://en.wikipedia.org/wiki/Xorshift">Wikipedia - XOR
	 *      Shift</a>
	 * @see <a href="http://en.wikipedia.org/wiki/George_Marsaglia"> George
	 *      Marsaglia</a>
	 * 
	 * @since 2003
	 */
	XOR_SHIFT(20) {

		{ // configure properties
			minlen.set(Randomness.INT_SIZE_BYTES);
			outlen.set(Randomness.INT_SIZE_BYTES);
			period = new AtomicInteger(160); // default
			seedlen.set(20);
		}

		@Override
		PseudorandomnessEngine newInstance() {
			return new XORShift();
		}

	}; // Needs 5 32-bit integers.

	// /////////////////////////////////////////////////////////////////
	// ///////////////////// SYNONYMS //////////////////////////////////
	// /////////////////////////////////////////////////////////////////

	/**
	 * Synonym of {@linkplain PRNG#LCG Linear Congruental} algorithm which
	 * {@link Random java.util.Random} is used.
	 */
	public static final PRNG UTIL_RANDOM = LCG;
	/**
	 * Represents native pseudorandom number generator nativelly suppotred by
	 * Java Platform - <code>java.util.Random</code> (also here as
	 * {@linkplain PRNG#LCG LCG}).
	 * 
	 * @see TRNG#NATIVE Native truerandomness
	 * @see CSPRNG#NATIVE Native cryptoranomdness
	 */
	public static final PRNG NATIVE = UTIL_RANDOM;
	/**
	 * Synonym of {@linkplain PRNG#MT Mersenne Twister} algorithm.
	 */
	public static final PRNG MERSENNE_TWISTER = MT;
	/**
	 * Synonym of 64-bit version of {@linkplain PRNG#MT64 Mersenne Twister}
	 * algorithm.
	 */
	public static final PRNG MERSENNE_TWISTER_64 = MT64;

	// /////////////////////////////////////////////////////////////////
	// ///////////////////// CONSTRUCTOR AND FACTORIES /////////////////
	// /////////////////////////////////////////////////////////////////

	private PRNG(int defaultSeedValue) {
		seedlen = new AtomicInteger(defaultSeedValue);
		outlen = new AtomicInteger();
		minlen = new AtomicInteger();
	}

	/**
	 * Default seed generator for PRNG
	 * {@linkplain Pseudorandomness#getEntropyInput(int) entropy input function}
	 * that uses Java's bundled {@link SecureRandom} (as instance of
	 * {@link TRNG#NATIVE}) source to generate random <i>seed</i> data with
	 * sufficient entropy. This is the only seeding strategy that is guaranteed
	 * to work on all platforms.
	 */
	public static final AtomicReference<Randomness> DEFAULT_ENTROPY_INPUT = new AtomicReference<Randomness>(
			NativeEntropy.INSTANCE); // DEFAULT_ENTROPY_INPUT

	/**
	 * Create's new instance of specified PRNG.
	 * 
	 * @return a new Pseudorandomness generator, or <code>null</code> if this
	 *         generator is not supported by platform at this time.
	 * 
	 */
	abstract PseudorandomnessEngine newInstance();

	/**
	 * Returns a new PRNG object shared across multiply threads allowing thread
	 * safe acess to generation methods.
	 * 
	 * @return a new Pseugorandomness generator.
	 */
	public Pseudorandomness shared() {
		return new PseudorandomnessSharedLock(this.newInstance());
	}

	/**
	 * Returns a <b>unique</b> PRNG generator isolated to the current thread
	 * (<i>thread local random</i>). Any attempt to use this instance from
	 * another thread will throw {@link ConcurrentModificationException}.
	 * <p>
	 * Usages of this class should typically be of the form:
	 * {@code PRNG.XXX.current().nextX(...)} (where {@code XXX} - one of
	 * implemented PRNG generators, and {@code X} is {@code Int}, {@code Long},
	 * etc). When all usages are of this form, it is never possible to
	 * accidently share a <i>thread local random</i> across multiple threads.
	 * <p>
	 * The thread local random instance is unique for parent thread, so locality
	 * can be cheked as:
	 * 
	 * <pre>
	 * public boolean isThreadLocal(Randomness rnd) {
	 * 	return PRNG.XXX.current() == rnd;
	 * }
	 * </pre>
	 * 
	 * where {@code XXX} - one of implemented PRNG generators
	 * 
	 * @return the thread local instance of PRNG for current thread.
	 * 
	 * @see ThreadLocal
	 * @see <br>
	 *      TRNG#current() Thread local for Truerandomness,
	 * @see <br>
	 *      CSPRNG#current() Thread-local for Cryptorandomness.
	 * 
	 */
	public final synchronized Pseudorandomness current() {
		return localRandom.get();
	}

	/**
	 * Returns the instance of specified PRNG prepeared to be a
	 * <i>thread-local</i>.
	 * 
	 * @return PRNG ready to be isolated into current thread.
	 */
	Pseudorandomness threadLocal() {
		return new PseudorandomnessThreadLocal(this.newInstance(),
				Thread.currentThread());
	}

	/**
	 * The actual ThreadLocal of Pseudorandomness instances
	 */
	private final ThreadLocal<Pseudorandomness> localRandom = new ThreadLocal<Pseudorandomness>() {
		protected Pseudorandomness initialValue() {
			return PRNG.this.threadLocal();
		}
	};

	// /////////////////////////////////////////////////////////////////
	// ///////////////////// CONFIGURATION VARIABLES ///////////////////
	// /////////////////////////////////////////////////////////////////

	/**
	 * Reference to PRNG seed length
	 */
	final AtomicInteger seedlen;
	/**
	 * Reference to PRNG output block
	 */
	final AtomicInteger outlen;
	/**
	 * Reference to PRNG minimum lenght
	 */
	final AtomicInteger minlen;
	/**
	 * Reference to PRNG current period.
	 */
	AtomicInteger period;

	// /////////////////////////////////////////////////////////////////
	// ///////////////////// INTERNAL INSTANCE /////////////////////////
	// /////////////////////////////////////////////////////////////////

	/**
	 * Internal instance of this PRNG.
	 */
	private Pseudorandomness instance;

	private synchronized void initRNG() {
		if (instance == null)
			instance = shared();
	}

	/**
	 * Resets internal instance of this PRNG to its <i>initial internal
	 * state</i>.
	 * <p>
	 * This method behaves exactly as specified in the {@linkplain #reseed()
	 * instantiate function}.
	 * <p>
	 * When this method is first called, it creates a single new PRNG, exactly
	 * as if by the expression new <code>PRNG.XXX.shared()</code> This new
	 * pseudorandom-number generator is used thereafter for all calls to this
	 * method and is used nowhere else.
	 * <p>
	 * The underlying PRNG is properly synchronized to allow correct use by more
	 * than one thread. However, if many threads need to generate pseudorandom
	 * numbers at a great rate, it may reduce contention for each thread to have
	 * its own {@linkplain #current() thread-local} pseudorandom-number
	 * generator.
	 */
	public final PRNG reset() {
		if (instance == null)
			initRNG();

		instance.reset();
		return this;
	}

	/**
	 * Reseed internal instance of this PRNG to new <i>initial internal
	 * state</i> using default entropy input.
	 * <p>
	 * This method behaves exactly as specified in the {@linkplain #reseed()
	 * reseed function}.
	 * <p>
	 * When this method is first called, it creates a single new PRNG, exactly
	 * as if by the expression new <code>PRNG.XXX.shared()</code> This new
	 * pseudorandom-number generator is used thereafter for all calls to this
	 * method and is used nowhere else.
	 * <p>
	 * The underlying PRNG is properly synchronized to allow correct use by more
	 * than one thread. However, if many threads need to generate pseudorandom
	 * numbers at a great rate, it may reduce contention for each thread to have
	 * its own {@linkplain #current() thread-local} pseudorandom-number
	 * generator.
	 * 
	 * @return <code>this</code>
	 */
	public final PRNG reseed() {
		if (instance == null)
			initRNG();

		instance.reseed();
		return this;
	}

	/**
	 * Reseed internal instance of this PRNG to new <i>initial internal
	 * state</i> using specifed seed bytes.
	 * <p>
	 * This method behaves exactly as specified in the {@linkplain #reseed()
	 * reseed function}.
	 * <p>
	 * When this method is first called, it creates a single new PRNG, exactly
	 * as if by the expression new <code>PRNG.XXX.shared()</code> This new
	 * pseudorandom-number generator is used thereafter for all calls to this
	 * method and is used nowhere else.
	 * <p>
	 * The underlying PRNG is properly synchronized to allow correct use by more
	 * than one thread. However, if many threads need to generate pseudorandom
	 * numbers at a great rate, it may reduce contention for each thread to have
	 * its own {@linkplain #current() thread-local} pseudorandom-number
	 * generator.
	 * 
	 * @return <code>this</code>
	 */
	public final PRNG reseed(ByteBuffer seed) {
		if (instance == null)
			initRNG();

		instance.reseed(seed);
		return this;
	}

	// ///////////////////////////////////////////////////////////////
	// ////////////////// GENERATE METHODS ///////////////////////////
	// ///////////////////////////////////////////////////////////////

	/**
	 * Return's next generated <code>boolean</code> with a specified probability
	 * of returning <code>true</code>, else returning <code>false</code>.
	 * <p>
	 * Uses 32-bit precision.
	 * 
	 * @param probability
	 *            <tt>probability</tt> must be between 0.0 and 1.0, inclusive.
	 * @return the <code>next</code> generated
	 */
	public final boolean nextProbability(final float probability) {
		if (probability < 0.0f || probability > 1.0f)
			throw new IllegalArgumentException(
					"probability must be between 0.0 and 1.0 inclusive.");
		if (probability == 0.0)
			return false; // fix half-open issues
		else if (probability == 1.0)
			return true; // fix half-open issues

		return ((nextInt() >>> 8) / ((float) (1 << 24))) < probability;
	}

	/**
	 * Return's next generated pseudorandom 32-bit <code>int</code> value.
	 * Returned values are chosen pseudorandomly with (approximately) uniform
	 * distribution from range {@link Integer#MIN_VALUE} to
	 * {@link Integer#MAX_VALUE}.
	 * <p>
	 * When this method is first called, it creates a single new PRNG, exactly
	 * as if by the expression new <code>PRNG.XXX.shared()</code> This new
	 * pseudorandom-number generator is used thereafter for all calls to this
	 * method and is used nowhere else.
	 * <p>
	 * The underlying PRNG is properly synchronized to allow correct use by more
	 * than one thread. However, if many threads need to generate pseudorandom
	 * numbers at a great rate, it may reduce contention for each thread to have
	 * its own {@linkplain #current() thread-local} pseudorandom-number
	 * generator.
	 * <p>
	 * There are several pseudorandom generators, essentially producing
	 * <code>int</code> values:
	 * <ol>
	 * <li> {@link PRNG#CELLULAR_AUTOMATON},
	 * <li> {@link PRNG#CELLULAR_AUTOMATON_192_RULE_30}
	 * <li> {@link PRNG#CMWC4096},
	 * <li> {@link PRNG#LCG},
	 * <li> {@link PRNG#MT},
	 * <li> {@link PRNG#SFMT},
	 * <li> {@link PRNG#WELL512a},{@link PRNG#WELL1024a},{@link PRNG#WELL19937c},
	 * {@link PRNG#WELL44497b}
	 * <li> {@link PRNG#XOR_SHIFT}
	 * </ol>
	 * 
	 * @return a pseudorandom <code>int</code> value.
	 */
	public final int nextInt() {
		if (instance == null)
			initRNG();

		return instance.nextInt();
	}

	/**
	 * Return's next generated pseudorandom 1-bit <code>boolean</code> value
	 * checking most significant bit. Returned values are chosen pseudorandomly
	 * with (approximately) uniform distribution from <code>true</code> or
	 * <code>false</code> with equal probability.
	 * <p>
	 * When this method is first called, it creates a single new PRNG, exactly
	 * as if by the expression new <code>PRNG.XXX.shared()</code> This new
	 * pseudorandom-number generator is used thereafter for all calls to this
	 * method and is used nowhere else.
	 * <p>
	 * The underlying PRNG is properly synchronized to allow correct use by more
	 * than one thread. However, if many threads need to generate pseudorandom
	 * numbers at a great rate, it may reduce contention for each thread to have
	 * its own {@linkplain #current() thread-local} pseudorandom-number
	 * generator.
	 * 
	 * @see <a href="http://en.wikipedia.org/wiki/Bit">Wikipedia - Bit</a>
	 * @see <a
	 *      href="http://java.sun.com/docs/books/jls/third_edition/html/typesValues.html#4.2.5">JLS
	 *      - 4.2.5 The boolean Type and boolean Values</a>
	 * @return a pseudorandom boolean value.
	 */

	public final boolean nextBoolean() {
		if (instance == null)
			initRNG();

		return instance.nextBoolean();
	}

	/**
	 * Return's next generated pseudorandom 8-bit <code>byte</code> value.
	 * Returned values are chosen pseudorandomly with (approximately) uniform
	 * distribution from range {@link Byte#MIN_VALUE} to {@link Byte#MAX_VALUE}.
	 * <p>
	 * When this method is first called, it creates a single new PRNG, exactly
	 * as if by the expression new <code>PRNG.XXX.shared()</code> This new
	 * pseudorandom-number generator is used thereafter for all calls to this
	 * method and is used nowhere else.
	 * <p>
	 * The underlying PRNG is properly synchronized to allow correct use by more
	 * than one thread. However, if many threads need to generate pseudorandom
	 * numbers at a great rate, it may reduce contention for each thread to have
	 * its own {@linkplain #current() thread-local} pseudorandom-number
	 * generator.
	 * 
	 * @see <a href="http://en.wikipedia.org/wiki/Byte">Wikipedia - Byte</a>
	 * @see <a
	 *      href="http://java.sun.com/docs/books/jls/third_edition/html/typesValues.html#4.2.1">JLS
	 *      - 4.2.1 Integral Types and Values</a>
	 * @return a pseudorandom <code>byte</code> value.
	 */

	public final byte nextByte() {
		if (instance == null)
			initRNG();

		return instance.nextByte();
	}

	/**
	 * Return's next generated pseudorandom unsigned 16-bit <code>char</code>
	 * value. Returned values are chosen pseudorandomly with (approximately)
	 * uniform distribution from range {@link Character#MIN_VALUE} to
	 * {@link Character#MAX_VALUE}.
	 * <p>
	 * When this method is first called, it creates a single new PRNG, exactly
	 * as if by the expression new <code>PRNG.XXX.shared()</code> This new
	 * pseudorandom-number generator is used thereafter for all calls to this
	 * method and is used nowhere else.
	 * <p>
	 * The underlying PRNG is properly synchronized to allow correct use by more
	 * than one thread. However, if many threads need to generate pseudorandom
	 * numbers at a great rate, it may reduce contention for each thread to have
	 * its own {@linkplain #current() thread-local} pseudorandom-number
	 * generator.
	 * 
	 * @see <a
	 *      href="http://java.sun.com/docs/books/jls/third_edition/html/typesValues.html#4.2.1">JLS
	 *      - 4.2.1 Integral Types and Values</a>
	 * 
	 * @return a random double greater than or equal to 0.0 and less than 1.0.
	 */

	public final char nextChar() {
		if (instance == null)
			initRNG();

		return instance.nextChar();
	}

	/**
	 * Return's next generated pseudorandom 64-bit <code>double</code> value
	 * between <code>0.0</code> (inclusive) and <code>1.0</code> (exclusive).
	 * Returned values are chosen pseudorandomly with (approximately) uniform
	 * distribution greater than or equal to <code>0.0</code> and less than
	 * <code>1.0</code>.
	 * <p>
	 * When this method is first called, it creates a single new PRNG, exactly
	 * as if by the expression new <code>PRNG.XXX.shared()</code> This new
	 * pseudorandom-number generator is used thereafter for all calls to this
	 * method and is used nowhere else.
	 * <p>
	 * The underlying PRNG is properly synchronized to allow correct use by more
	 * than one thread. However, if many threads need to generate pseudorandom
	 * numbers at a great rate, it may reduce contention for each thread to have
	 * its own {@linkplain #current() thread-local} pseudorandom-number
	 * generator.
	 * <p>
	 * There are several PRNGs, essentially producing <code>double</code>
	 * values:
	 * <ol>
	 * <li> {@link PRNG#dSFMT2},
	 * <li> {@link PRNG#BAILEY_CRANDALL},
	 * </ol>
	 * 
	 * @see <a
	 *      href="http://java.sun.com/docs/books/jls/third_edition/html/typesValues.html#4.2.3">JLS
	 *      - 4.2.3 Floating-Point Types, Formats, and Values</a>
	 * @see <a href="http://en.wikipedia.org/wiki/IEEE_754-2008">Wikipedia -
	 *      IEEE 754</a>
	 * @return newly generated pseudorandom <code>double</code> value.
	 */

	public final double nextDouble() {
		if (instance == null)
			initRNG();

		return instance.nextDouble();
	}

	/**
	 * Return's next generated pseudorandom 32-bit <code>float</code> value
	 * between <code>0.0</code> (inclusive) and <code>1.0</code> (exclusive).
	 * Returned values are chosen pseudorandomly with (approximately) uniform
	 * distribution greater than or equal to <code>0.0</code> and less than
	 * <code>1.0</code>.
	 * <p>
	 * When this method is first called, it creates a single new PRNG, exactly
	 * as if by the expression new <code>PRNG.XXX.shared()</code> This new
	 * pseudorandom-number generator is used thereafter for all calls to this
	 * method and is used nowhere else.
	 * <p>
	 * The underlying PRNG is properly synchronized to allow correct use by more
	 * than one thread. However, if many threads need to generate pseudorandom
	 * numbers at a great rate, it may reduce contention for each thread to have
	 * its own {@linkplain #current() thread-local} pseudorandom-number
	 * generator.
	 * 
	 * @see <a
	 *      href="http://java.sun.com/docs/books/jls/third_edition/html/typesValues.html#4.2.3">JLS
	 *      - 4.2.3 Floating-Point Types, Formats, and Values</a>
	 * @see <a href="http://en.wikipedia.org/wiki/IEEE_754-2008">Wikipedia -
	 *      IEEE 754</a>
	 * @return newly generated pseudorandom <code>float</code> value.
	 */

	public final float nextFloat() {
		if (instance == null)
			initRNG();

		return instance.nextFloat();
	}

	/**
	 * Return's next generated pseudorandom 64-bit <code>long</code> value.
	 * Returned values are chosen pseudorandomly with (approximately) uniform
	 * distribution from range {@link Long#MIN_VALUE} to {@link Long#MAX_VALUE}.
	 * <p>
	 * When this method is first called, it creates a single new PRNG, exactly
	 * as if by the expression new <code>PRNG.XXX.shared()</code> This new
	 * pseudorandom-number generator is used thereafter for all calls to this
	 * method and is used nowhere else.
	 * <p>
	 * The underlying PRNG is properly synchronized to allow correct use by more
	 * than one thread. However, if many threads need to generate pseudorandom
	 * numbers at a great rate, it may reduce contention for each thread to have
	 * its own {@linkplain #current() thread-local} pseudorandom-number
	 * generator.
	 * <p>
	 * There are several pseudorandom generators, essentially producing
	 * <code>long</code> values:
	 * <ol>
	 * <li> {@link PRNG#COMBINED},
	 * <li> {@link PRNG#MT64}
	 * </ol>
	 * 
	 * @return a pseudorandom <code>long</code> value.
	 */

	public final long nextLong() {
		if (instance == null)
			initRNG();

		return instance.nextLong();
	}

	/**
	 * Return's next generated pseudorandom 16-bit <code>short</code> value.
	 * Returned values are chosen pseudorandomly with (approximately) uniform
	 * distribution from range {@link Short#MIN_VALUE} to
	 * {@link Short#MAX_VALUE}.
	 * <p>
	 * When this method is first called, it creates a single new PRNG, exactly
	 * as if by the expression new <code>PRNG.XXX.shared()</code> This new
	 * pseudorandom-number generator is used thereafter for all calls to this
	 * method and is used nowhere else.
	 * <p>
	 * The underlying PRNG is properly synchronized to allow correct use by more
	 * than one thread. However, if many threads need to generate pseudorandom
	 * numbers at a great rate, it may reduce contention for each thread to have
	 * its own {@linkplain #current() thread-local} pseudorandom-number
	 * generator.
	 * 
	 * @see <a href="http://en.wikipedia.org/wiki/Byte">Wikipedia - Byte</a>
	 * @see <a
	 *      href="http://java.sun.com/docs/books/jls/third_edition/html/typesValues.html#4.2.1">JLS
	 *      - 4.2.1 Integral Types and Values</a>
	 * @return a pseudorandom <code>short</code> value.
	 */

	public final short nextShort() {
		if (instance == null)
			initRNG();

		return instance.nextShort();
	}

	/**
	 * Generates random block of pseudorandom bytes and places them into a
	 * user-supplied byte array.
	 * 
	 * @param bytes
	 *            - the byte array to fill with pseudorandom bytes
	 */

	public final void read(byte[] bytes) {
		if (instance == null)
			initRNG();

		instance.read(bytes);
	}

	/**
	 * Reads a sequence of pseudorandom bytes from this PRNG into the given
	 * buffer.
	 * <p>
	 * Transfers a sequence generated bytes from this PRNG into the given
	 * buffer. An attempt is made to read up to <i>r</i> bytes from PRNG, where
	 * <i>r</i> is the number of bytes <i>remaining</i> in the buffer, that is,
	 * <tt>buffer.remaining()</tt>, at the moment this method is invoked.
	 * <p>
	 * Suppose that a byte sequence of length <i>n</i> is read, where <tt>0</tt>
	 * &nbsp;<tt>&lt;=</tt>&nbsp;<i>n</i>&nbsp;<tt>&lt;=</tt>&nbsp;<i>r</i>.
	 * This byte sequence will be transferred into the buffer so that the first
	 * byte in the sequence is at index <i>p</i> and the last byte is at index
	 * <i>p</i>&nbsp;<tt>+</tt>&nbsp;<i>n</i>&nbsp;<tt>-</tt>&nbsp;<tt>1</tt>,
	 * where <i>p</i> is the buffer's position at the moment this method is
	 * invoked. Upon return the buffer's position will be equal to
	 * <i>p</i>&nbsp;<tt>+</tt>&nbsp;<i>n</i>; its limit will not have changed.
	 * As many bytes as possible are transferred into each buffer, hence the
	 * final position is guaranteed to be equal to that buffer's limit.
	 * <p>
	 * When this method is first called, it creates a single new PRNG, exactly
	 * as if by the expression new <code>PRNG.XXX.shared()</code> This new
	 * pseudorandom-number generator is used thereafter for all calls to this
	 * method and is used nowhere else.
	 * <p>
	 * The underlying PRNG is properly synchronized to allow correct use by more
	 * than one thread. However, if many threads need to generate pseudorandom
	 * numbers at a great rate, it may reduce contention for each thread to have
	 * its own {@linkplain #current() thread-local} pseudorandom-number
	 * generator.
	 * 
	 * @param buffer
	 *            The buffer into which random bytes are to be transferred.
	 * 
	 * @return The number of bytes read from PRNG.
	 * 
	 * @throws NullPointerException
	 *             if <code>buffer</code> is <code>null</code>.
	 * 
	 * 
	 */
	public final int read(ByteBuffer buffer) {
		if (instance == null)
			initRNG();

		return instance.read(buffer);
	}

	/**
	 * Transfers a sequence of generated pseudorandom <code>int</code>'s from
	 * this PRNG into the given buffer.
	 * <p>
	 * Otherwise this method behaves exactly as specified in the
	 * {@linkplain #read(ByteBuffer)} method.
	 * 
	 * @param intBuffer
	 *            The buffer into which random integers are to be transferred
	 * @return The number of <code>int</code>'s read, possibly zero.
	 */
	public final int read(IntBuffer intBuffer) {
		if (instance == null)
			initRNG();

		return instance.read(intBuffer);
	}

	/**
	 * Transfers a sequence of generated pseudorandom <code>float</code>'s from
	 * this PRNG into the given buffer.
	 * <p>
	 * This method behaves exactly as specified in the
	 * {@linkplain #read(ByteBuffer)} method.
	 * 
	 * @param floatBuffer
	 *            The buffer into which random floating point values are to be
	 *            transferred
	 * @return The number of <code>float</code>'s read, possibly zero.
	 */
	public final int read(FloatBuffer floatBuffer) {
		if (instance == null)
			initRNG();

		return instance.read(floatBuffer);
	}

	/**
	 * Transfers a sequence of generated <code>long</code>'s from this PRNG into
	 * the given buffer.
	 * 
	 * <p>
	 * This method behaves exactly as specified in the
	 * {@linkplain #read(ByteBuffer)} method.
	 * 
	 * @param longBuffer
	 *            The buffer into which random <code>long</code> values are to
	 *            be transferred.
	 * @return The number of <code>long</code>'s read.
	 */
	public final int read(LongBuffer longBuffer) {
		if (instance == null)
			initRNG();

		return instance.read(longBuffer);
	}

	/**
	 * Transfers a sequence of generated <code>double</code>'s from this PRNG
	 * into the given buffer.
	 * <p>
	 * This method behaves exactly as specified in the
	 * {@linkplain #read(ByteBuffer)} method.
	 * 
	 * @param doubleBuffer
	 *            The buffer into which random <code>double</code>'s are to be
	 *            transferred
	 * @return The number of <code>double</code>'s read.
	 */
	public final int read(DoubleBuffer doubleBuffer) {
		if (instance == null)
			initRNG();

		return instance.read(doubleBuffer);
	}

	/**
	 * Returns a <code>double</code> value with a positive sign, greater than or
	 * equal to <code>0.0</code> and less than <code>1.0</code> (as in
	 * <code>java.lang.Math</code>). Returned values are chosen randomly with
	 * (approximately) uniform distribution from that range.
	 * <p>
	 * When this method is first called, it creates a single new PRNG, exactly
	 * as if by the expression new <code>PRNG.shared()</code> This new
	 * pseudorandom-number generator is used thereafter for all calls to this
	 * method and is used nowhere else.
	 * <p>
	 * The underlying PRNG is properly synchronized to allow correct use by more
	 * than one thread. However, if many threads need to generate pseudorandom
	 * numbers at a great rate, it may reduce contention for each thread to have
	 * its own pseudorandom-number generator.
	 * 
	 * 
	 * @return a random double greater than or equal to <code>0.0</code> and
	 *         less than <code>1.0</code>.
	 */
	public final double random() {
		if (instance == null)
			initRNG();

		return instance.nextDouble();
	}

	private static final int SHUFFLE_THRESHOLD = 5;

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
	 * Return's next generated pseudorandom 32-bit <code>int</code> value chosen
	 * pseudorandomly with (approximately) uniform distribution from range
	 * <code>0</code> (inclusive) to <code>n</code> (exclusive).
	 * <p>
	 * Suffice it to say, n must be > 0, or an IllegalArgumentException is
	 * raised.
	 * 
	 * @return a pseudorandom <code>int</code> value in range
	 *         <code>[0...n-1]</code>.
	 * 
	 * @throws IllegalArgumentException
	 *             if <code>n < 0</code>
	 */
	public final int nextInt(final int n) {
		if (n <= 0)
			throw new IllegalArgumentException("n must be > 0");

		return (int) ((n * (long) (nextInt() >>> 1)) >> 31);
	}

	/**
	 * Return's next generated pseudorandom 64-bit floating point
	 * <code>double</code> value chosen pseudorandomly with (approximately)
	 * uniform distribution from open interval <tt>[from,to]</tt> (excluding
	 * <tt>from</tt> and <tt>to</tt>).
	 * 
	 * @param from
	 *            low border of interval (excluded)
	 * @param to
	 *            hight border of interval (excluded)
	 * 
	 * @return a pseudorandom <code>long</code> value in range
	 *         <code>[0...n-1]</code>.
	 * 
	 * @throws IllegalArgumentException
	 *             if <tt>from >= to</tt>.
	 * @return next generated uniformly distributed random number in interval
	 *         <tt>[from,to]</tt>.
	 */
	public final double nextDouble(double from, double to) {
		if (from >= to)
			throw new IllegalArgumentException("upper bound (" + to
					+ ") must be greater than lower bound (" + from + ")");

		// The implementation is inspired from Cern's Colt Jet Random
		return from + (to - from) * nextDouble();
	}

	/**
	 * Return's next generated pseudorandom 32-bit floating-point
	 * <code>float</code> value chosen pseudorandomly with (approximately)
	 * uniform distribution from open interval <tt>[from,to]</tt> (excluding
	 * <tt>from</tt> and <tt>to</tt>).
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
	 * Return's next generated pseudorandom 64-bit <code>long</code> value
	 * chosen pseudorandomly with (approximately) uniform distribution from
	 * range <code>0 </code> (inclusive) to <code>n</code> (exclusive).
	 * <p>
	 * Suffice it to say, n must be > 0, or an IllegalArgumentException is
	 * raised.
	 * 
	 * @return a pseudorandom <code>long</code> value in range
	 *         <code>[0...n-1]</code>.
	 * 
	 * @throws IllegalArgumentException
	 *             if <code>n < 0</code>
	 */
	public final long nextLong(final long n) {
		if (n <= 0)
			throw new IllegalArgumentException("n must be > 0");

		long bits, val;
		do {
			bits = (((((long) nextInt()) << 32) + (long) nextInt()) >>> 1);
			val = bits % n;
		} while (bits - val + (n - 1) < 0);
		return val;
	}

	/**
	 * Return's next generated pseudorandom 64-bit <code>long</code> value
	 * chosen pseudorandomly with (approximately) uniform distribution from
	 * closed interval <tt>[from,to]</tt> (including <tt>from</tt> and
	 * <tt>to</tt>).
	 * 
	 * @param from
	 *            low border of interval (included)
	 * @param to
	 *            hight border of interval (included)
	 * 
	 * @return a pseudorandom <code>long</code> value in range
	 *         <code>[0...n-1]</code>.
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
	 * 
	 * Determine default initial <i>seed length</i> used by underlying DRBG
	 * algorithm in bytes <i>(not configurable)</i>.
	 * <p>
	 * Note that seed length value is essential part of PRNG itself depending on
	 * its nature.
	 * 
	 * @return seed length in bytes
	 */
	public final int seedlen() {
		return seedlen.get();
	}

	/**
	 * Determine PRNG <i>generation cycle</i> - Generation cycle - it is a
	 * number of bytes generated between two modifications of working state.
	 * <p>
	 * If PRNG is closed in arbitrary moment, the returned number of generated
	 * bytes <code>G</code> not less than <code>G >= N * outlen</code>, where
	 * <code>N</code> - it is a number of generation cycles done by generate
	 * function.
	 * 
	 * @return PRNG output block value
	 */
	public final int outlen() {
		return outlen.get();
	}

	/**
	 * Determine PRNG {@linkplain Randomness#minlen() minlen} - size of minimum
	 * pseudorandom bitstring generated per iteration.
	 * <p>
	 * Note that minlen value is essential part of PRNG itself depending on its
	 * nature.
	 * 
	 * @return minlen in bytes
	 */
	public final int minlen() {
		return minlen.get();
	}

	/**
	 * Determine current PRNG period value <i>n</i>, such as actual period is
	 * 2<sup>n</sup>.
	 * 
	 * @return period value of specified PRNG
	 */
	public final int period() {
		return period != null ? period.get() : 0;
	}

}
