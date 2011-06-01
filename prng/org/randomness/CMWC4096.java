package org.randomness;

import java.nio.ByteBuffer;
import java.nio.DoubleBuffer;
import java.nio.FloatBuffer;
import java.nio.IntBuffer;
import java.nio.LongBuffer;
import java.util.Arrays;

/**
 * <p>
 * A Java version of George Marsaglia's <a href=
 * "http://school.anhb.uwa.edu.au/personalpages/kwessen/shared/Marsaglia03.html"
 * >Complementary Multiply With Carry (CMWC) RNG</a>. This is a very fast PRNG
 * with an extremely long period (2^131104). It should be used in preference to
 * the MersenneTwister RNG when a very long period is required.
 * </p>
 * 
 * <p>
 * One potential drawback of this RNG is that it requires significantly more
 * seed data than the other RNGs provided by Uncommons Maths. It requires just
 * over 16 kilobytes, which may be a problem if your are obtaining seed data
 * from a slow or limited entropy source. In contrast, the Mersenne Twister
 * requires only 128 bits of seed data.
 * </p>
 * 
 * @author Daniel Dyer (uncommons-math)
 * @author Anton Kabysh
 */
final class CMWC4096 extends PseudorandomnessEngine {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	private static final long A = 18782L;

	private final int[] state = new int[4096];
	private int carry = 362436;
	private int index = 4095;

	private IntBuffer stateArray;

	public CMWC4096() {
		this.reset();
	}

	@Override
	protected final void instantiate(ByteBuffer seed) {
		// //////////////// INSTANTIATE FUNCTION ////////////////////////

		// carry = seed.getInt(); // randomly
		carry = 362436;
		index = 4095;

		Arrays.fill(state, 0);

		for (int i = 0; i < state.length; i++) {
			state[i] = seed.getInt();
		}
		// //////////////// INSTANTIATE FUNCTION ////////////////////////
	}

	@Override
	public final int read(ByteBuffer buffer) {
		final int numBytes = buffer.remaining();

		int bytes = 0;

		for (; (numBytes - bytes) >= INT_SIZE_BYTES;) {

			if (shared && !isOpen()) // check interruption status
				return bytes; // interrupt

			// ///////////////// GENERATE FUNCTION /////////////////////
			int[] state = this.state;
			index = (index + 1) & 4095;
			long t = A * (state[index] & 0xFFFFFFFFL) + carry;
			carry = (int) (t >> 32);
			int x = ((int) t) + carry;
			if (x < carry) {
				x++;
				carry++;
			}
			state[index] = 0xFFFFFFFE - x;
			// ///////////////// GENERATE FUNCTION /////////////////////
			buffer.putInt(state[index]);
			bytes += INT_SIZE_BYTES; // inc bytes

		}

		if (bytes < numBytes) {
			// put last bytes
			int rnd = generate32();

			for (int n = numBytes - bytes; n-- > 0; bytes++)
				buffer.put((byte) (rnd >>> (Byte.SIZE * n)));
		}

		return numBytes - buffer.remaining() /* should be zero */;
	}

	@Override
	public final int read(IntBuffer intBuffer) {
		final int numInts = intBuffer.remaining();

		int ints = 0;

		for (; ints < numInts;) {

			if (shared && !isOpen()) // check interruption status
				return ints; // interrupt

			// ///////////////// GENERATE FUNCTION /////////////////////
			int[] state = this.state;
			index = (index + 1) & 4095;
			long t = A * (state[index] & 0xFFFFFFFFL) + carry;
			carry = (int) (t >> 32);
			int x = ((int) t) + carry;
			if (x < carry) {
				x++;
				carry++;
			}
			state[index] = 0xFFFFFFFE - x;
			// ///////////////// GENERATE FUNCTION /////////////////////

			intBuffer.put(state[index]);
			ints++;
		}

		return numInts - intBuffer.remaining();
	}

	@Override
	public final int read(FloatBuffer floatBuffer) {

		final int numFloats = floatBuffer.remaining();

		int floats = 0;

		for (; floats < numFloats;) {

			if (shared && !isOpen()) // check interruption status
				return floats; // interrupt

			// ///////////////// GENERATE FUNCTION /////////////////////
			int[] state = this.state;
			index = (index + 1) & 4095;
			long t = A * (state[index] & 0xFFFFFFFFL) + carry;
			carry = (int) (t >> 32);
			int x = ((int) t) + carry;
			if (x < carry) {
				x++;
				carry++;
			}
			state[index] = 0xFFFFFFFE - x;
			// ///////////////// GENERATE FUNCTION /////////////////////
			floatBuffer.put((state[index] >>> 8) / ((float) (1 << 24)));
			floats++;
		}

		return numFloats - floatBuffer.remaining();
	}

	@Override
	public final int read(LongBuffer longBuffer) {

		final int numLongs = longBuffer.remaining();

		for (int longs = 0; longs < numLongs; longs++) {

			if (shared && !isOpen()) // check interruption status
				return longs; // interrupt

			int l;
			int r;
			// ///////////////// GENERATE FUNCTION /////////////////////
			{
				int[] state = this.state;
				index = (index + 1) & 4095;
				long t = A * (state[index] & 0xFFFFFFFFL) + carry;
				carry = (int) (t >> 32);
				int x = ((int) t) + carry;
				if (x < carry) {
					x++;
					carry++;
				}
				state[index] = 0xFFFFFFFE - x;
			}
			l = state[index];

			// ///////////////// GENERATE FUNCTION /////////////////////
			{
				index = (index + 1) & 4095;
				long t = A * (state[index] & 0xFFFFFFFFL) + carry;
				carry = (int) (t >> 32);
				int x = ((int) t) + carry;
				if (x < carry) {
					x++;
					carry++;
				}
				state[index] = 0xFFFFFFFE - x;
			}
			r = state[index];
			// ///////////////// GENERATE FUNCTION /////////////////////
			longBuffer.put((((long) l) << 32) + r);

		}

		return numLongs - longBuffer.remaining();
	}

	@Override
	public final int read(DoubleBuffer doubleBuffer) {

		final int numDoubles = doubleBuffer.remaining();

		int doubles = 0;

		for (; doubles < numDoubles;) {

			if (shared && !isOpen()) // check interruption status
				return doubles; // interrupt

			int l;
			int r;
			// ///////////////// GENERATE FUNCTION /////////////////////
			{
				int[] state = this.state;
				index = (index + 1) & 4095;
				long t = A * (state[index] & 0xFFFFFFFFL) + carry;
				carry = (int) (t >> 32);
				int x = ((int) t) + carry;
				if (x < carry) {
					x++;
					carry++;
				}
				state[index] = 0xFFFFFFFE - x;
			}
			l = state[index];
			{
				index = (index + 1) & 4095;
				long t = A * (state[index] & 0xFFFFFFFFL) + carry;
				carry = (int) (t >> 32);
				int x = ((int) t) + carry;
				if (x < carry) {
					x++;
					carry++;
				}
				state[index] = 0xFFFFFFFE - x;
			}
			r = state[index];
			// ///////////////// GENERATE FUNCTION /////////////////////
			doubleBuffer.put(((((long) (l >>> 6)) << 27) + (r >>> 5))
					/ (double) (1L << 53));
			doubles++;
		}

		return numDoubles - doubleBuffer.remaining() /* should be zero */;

	}

	@Override
	public final int nextInt() {
		int[] state = this.state;
		index = (index + 1) & 4095;
		long t = A * (state[index] & 0xFFFFFFFFL) + carry;
		carry = (int) (t >> 32);
		int x = ((int) t) + carry;
		if (x < carry) {
			x++;
			carry++;
		}
		state[index] = 0xFFFFFFFE - x;
		return state[index];

	}

	@Override
	public final float nextFloat() {
		int[] state = this.state;
		index = (index + 1) & 4095;
		long t = A * (state[index] & 0xFFFFFFFFL) + carry;
		carry = (int) (t >> 32);
		int x = ((int) t) + carry;
		if (x < carry) {
			x++;
			carry++;
		}
		state[index] = 0xFFFFFFFE - x;

		return (state[index] >>> 8) / ((float) (1 << 24));
	}

	@Override
	public final long nextLong() {
		int l;
		int r;
		// ///////////////// GENERATE FUNCTION /////////////////////
		{
			int[] state = this.state;
			index = (index + 1) & 4095;
			long t = A * (state[index] & 0xFFFFFFFFL) + carry;
			carry = (int) (t >> 32);
			int x = ((int) t) + carry;
			if (x < carry) {
				x++;
				carry++;
			}
			state[index] = 0xFFFFFFFE - x;
		}
		l = state[index];

		// ///////////////// GENERATE FUNCTION /////////////////////
		{
			index = (index + 1) & 4095;
			long t = A * (state[index] & 0xFFFFFFFFL) + carry;
			carry = (int) (t >> 32);
			int x = ((int) t) + carry;
			if (x < carry) {
				x++;
				carry++;
			}
			state[index] = 0xFFFFFFFE - x;
		}
		r = state[index];
		// ///////////////// GENERATE FUNCTION /////////////////////
		return (((long) l) << 32) + r;
	}

	@Override
	public final double nextDouble() {
		int l;
		int r;
		// ///////////////// GENERATE FUNCTION /////////////////////
		{
			int[] state = this.state;
			index = (index + 1) & 4095;
			long t = A * (state[index] & 0xFFFFFFFFL) + carry;
			carry = (int) (t >> 32);
			int x = ((int) t) + carry;
			if (x < carry) {
				x++;
				carry++;
			}
			state[index] = 0xFFFFFFFE - x;
		}
		l = state[index];

		// ///////////////// GENERATE FUNCTION /////////////////////
		{
			index = (index + 1) & 4095;
			long t = A * (state[index] & 0xFFFFFFFFL) + carry;
			carry = (int) (t >> 32);
			int x = ((int) t) + carry;
			if (x < carry) {
				x++;
				carry++;
			}
			state[index] = 0xFFFFFFFE - x;
		}
		r = state[index];
		// ///////////////// GENERATE FUNCTION /////////////////////
		return ((((long) (l >>> 6)) << 27) + (r >>> 5)) / (double) (1L << 53);
	}

	private final int generate32() {
		index = (index + 1) & 4095;
		long t = A * (state[index] & 0xFFFFFFFFL) + carry;
		carry = (int) (t >> 32);
		int x = ((int) t) + carry;
		if (x < carry) {
			x++;
			carry++;
		}
		state[index] = 0xFFFFFFFE - x;
		return state[index];
	}

	@Override
	public final String toString() {
		return PRNG.CMWC4096.name();
	}

	@Override
	public final int hashCode() {
		if (stateArray == null)
			stateArray = IntBuffer.wrap(state);

		stateArray.clear();
		int hash = 31 * stateArray.hashCode() + carry;
		return 31 * hash + index;

	}

	@Override
	public final boolean equals(Object obj) {
		if (obj == null)
			return false;

		if (!(obj instanceof CMWC4096))
			return false;

		if (!this.isOpen())
			return false;

		if (this == obj)
			return true;

		CMWC4096 that = (CMWC4096) obj;

		if (!that.isOpen())
			return false;

		return this.index == that.index && this.carry == that.carry
				&& this.hashCode() == that.hashCode()
				&& this.stateArray.clear().equals(that.stateArray.clear());
	}

	@Override
	public final CMWC4096 copy() {
		CMWC4096 copy = new CMWC4096();

		copy.reseed((ByteBuffer) this.mark.clear());
		copy.carry = this.carry;
		copy.index = this.index;

		System.arraycopy(this.state, 0, copy.state, 0, this.state.length);

		return copy;
	}

	@Override
	public final int minlen() {
		return INT_SIZE_BYTES;
	}

}
