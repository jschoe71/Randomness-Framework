package org.randomness;

import java.nio.ByteBuffer;

/**
 * This class specify <i>Quasirandom Number Generator</i> techniques for
 * quasirandom analogue of a random process which is a deterministic process
 * specifically designed so that simulation of the quasirandom process gives the
 * same limiting behavior (of some quantities of interest) as the random
 * process, but with faster convergence. <br>
 * <h3><i>PROVISIONAL API, WORK IN PROGRESS</i></h3> (Quasirandomness is not to
 * be confused with pseudorandomness. A pseudorandom process is supposed to be
 * statistically indistinguishable from the truly random process it imitates. In
 * contrast, a quasirandom process will typically have many regularities that
 * mark it as non-random. Quasirandom processes only need to be irregular
 * <i>enough</i> for the desired application.)
 * <p>
 * Most work on quasirandomness (also sometimes called <i>subrandomness</i>) has
 * been motivated by Monte Carlo integration, and involves well-distributed
 * sequences of points in some continuous space (e.g., the sequence of points in
 * the interval [0,1] whose <i>n</i>th element is
 * <i>a</i><sub>0</sub>/2&nbsp;+&nbsp;<i>a</i><sub>1</sub>/4&nbsp;+&nbsp;<i>a</i
 * ><sub>2</sub>/8&nbsp;+&nbsp;..., where <i>n</i> =
 * <i>a</i><sub>0</sub>&nbsp;+&nbsp;2<i>a</i><sub>1</sub>&nbsp;+&nbsp;4<i>a</i><
 * sub>2</sub>+&nbsp;..., or the sequence whose <i>n</i>th element is the
 * fractional part of <i>n</i> times the golden ratio).
 * <p>
 * A series of numbers satisfying some mathematical random properties even
 * though no random appearance is provided Good for Monte-Carlo methods Lower
 * discrepancies offer better convergence
 * 
 * @author Антон
 * 
 */
public abstract class Quasirandomess extends Randomness {

	@Override
	public boolean isOpen() {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public void reset() {
		// TODO Auto-generated method stub

	}

	@Override
	public int read(ByteBuffer dst) {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	public void close() {
		// TODO Auto-generated method stub

	}

	@Override
	public String toString() {
		// TODO Auto-generated method stub
		return null;
	}

	/**
	 * Apply the baker's transformation to the output of this QRBG. It
	 * transforms each <SPAN CLASS="MATH"><I>u</I>&#8712;[0, 1]</SPAN> into
	 * <SPAN CLASS="MATH">2<I>u</I></SPAN> if <SPAN
	 * CLASS="MATH"><I>u</I>&nbsp;&lt;=&nbsp;1/2</SPAN> and <SPAN
	 * CLASS="MATH">2(1 - <I>u</I>)</SPAN> if <SPAN CLASS="MATH"><I>u</I> &gt;
	 * 1/2</SPAN>. *
	 * <P>
	 * The baker transformation is often applied when the QRBG is actually an
	 * iterator over a point set used for quasi-Monte Carlo integration.
	 * 
	 * @see <a href="http://en.wikipedia.org/wiki/Baker's_map">Wikipedia -
	 *      Baker's Map</a>
	 * @return the baker transformation over this QRBG.
	 */
	public Quasirandomess bakerTransformation() {
		return this;

	}

	@Override
	public int tryRead(ByteBuffer buffer) {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	public int minlen() {
		// TODO Auto-generated method stub
		return 0;
	}

}
