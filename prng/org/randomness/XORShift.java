// ============================================================================
//   Copyright 2006-2009 Daniel W. Dyer
//   Original source code adopted to Randomness Framework by Anton Kabysh.
//
//   Licensed under the Apache License, Version 2.0 (the "License");
//   you may not use this file except in compliance with the License.
//   You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//   See the License for the specific language governing permissions and
//   limitations under the License.
// ============================================================================
package org.randomness;

import java.nio.ByteBuffer;
import java.nio.DoubleBuffer;
import java.nio.FloatBuffer;
import java.nio.IntBuffer;
import java.nio.LongBuffer;

/**
 * Very fast pseudo random number generator. See <a href=
 * "http://school.anhb.uwa.edu.au/personalpages/kwessen/shared/Marsaglia03.html"
 * >this page</a> for a description. This RNG has a period of about 2^160, which
 * is not as long as the {@link MT} but it is faster.
 * 
 * @author Anton Kabysh (randomness framework adaptation)
 * @author Daniel Dyer (uncommons-math XORShiftRNG)
 * @author George Marsaglia
 */
final class XORShift extends PseudorandomnessEngine {

	// Previously used an array for state but using separate fields proved to be
	// faster.

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	private int state1;
	private int state2;
	private int state3;
	private int state4;
	private int state5;

	/**
	 * Creates an RNG and seeds it with the specified seed data.
	 * 
	 * @param seed
	 *            The seed data used to initialize the RNG.
	 */
	public XORShift() {
		this.reset();
	}

	@Override
	protected final void instantiate(ByteBuffer seed) {
		// //////////////// INSTANTIATE FUNCTION ////////////////////////
		this.state1 = seed.getInt();
		this.state2 = seed.getInt();
		this.state3 = seed.getInt();
		this.state4 = seed.getInt();
		this.state5 = seed.getInt();
		// //////////////// INSTANTIATE FUNCTION ////////////////////////
	}

	@Override
	public final int read(byte[] bytes) {
		int i = 0;
		final int iEnd = bytes.length - 3;
		while (i < iEnd) {

			if (!isOpen()) // check interruption status
				return i;

			final int random = generate32();
			bytes[i] = (byte) (random & 0xff);
			bytes[i + 1] = (byte) ((random >> 8) & 0xff);
			bytes[i + 2] = (byte) ((random >> 16) & 0xff);
			bytes[i + 3] = (byte) ((random >> 24) & 0xff);
			i += 4;
		}

		int random = generate32();
		while (i < bytes.length) {
			bytes[i++] = (byte) (random & 0xff);
			random = random >> 8;
		}

		return bytes.length;
	}

	@Override
	public final int read(ByteBuffer buffer) {
		final int numBytes = buffer.remaining();

		int bytes = 0;

		for (; (numBytes - bytes) >= INT_SIZE_BYTES;) {

			if (!isOpen()) // check interruption status
				return bytes; // interrupt

			// ///////////////// GENERATE FUNCTION /////////////////////
			int t = (state1 ^ (state1 >> 7));
			state1 = state2;
			state2 = state3;
			state3 = state4;
			state4 = state5;
			state5 = (state5 ^ (state5 << 6)) ^ (t ^ (t << 13));
			// ///////////////// GENERATE FUNCTION /////////////////////

			buffer.putInt((state2 + state2 + 1) * state5);
			bytes += INT_SIZE_BYTES; // inc bytes

		}

		if (bytes < numBytes) {
			// put last bytes
			int rnd = generate32();

			for (int n = numBytes - bytes; n-- > 0; bytes++)
				buffer.put((byte) (rnd >>> (Byte.SIZE * n)));
		}

		return numBytes - buffer.remaining();

	}

	@Override
	public final int read(IntBuffer intBuffer) {

		final int numInts = intBuffer.remaining();

		int ints = 0;

		for (; ints < numInts;) {

			if (!isOpen()) // check interruption status
				return ints; // interrupt

			// ///////////////// GENERATE FUNCTION /////////////////////
			int t = (state1 ^ (state1 >> 7));
			state1 = state2;
			state2 = state3;
			state3 = state4;
			state4 = state5;
			state5 = (state5 ^ (state5 << 6)) ^ (t ^ (t << 13));
			// ///////////////// GENERATE FUNCTION /////////////////////

			intBuffer.put((state2 + state2 + 1) * state5);
			ints++;
		}

		return numInts - intBuffer.remaining();
	}

	@Override
	public final int read(FloatBuffer floatBuffer) {

		final int numFloats = floatBuffer.remaining();

		int floats = 0;

		for (; floats < numFloats;) {

			if (!isOpen()) // check interruption status
				return floats; // interrupt

			// ///////////////// GENERATE FUNCTION /////////////////////
			int t = (state1 ^ (state1 >> 7));
			state1 = state2;
			state2 = state3;
			state3 = state4;
			state4 = state5;
			state5 = (state5 ^ (state5 << 6)) ^ (t ^ (t << 13));
			// ///////////////// GENERATE FUNCTION /////////////////////

			floatBuffer.put((((state2 + state2 + 1) * state5) >>> 8)
					/ ((float) (1 << 24)));
			floats++;
		}

		return numFloats - floatBuffer.remaining();
	}

	@Override
	public final int read(LongBuffer longBuffer) {
		final int numLongs = longBuffer.remaining();

		for (int longs = 0; longs < numLongs;) {

			if (!isOpen()) // check interruption status
				return longs; // interrupt

			int l;
			int r;

			// ///////////////// GENERATE FUNCTION /////////////////////
			{

				int t = (state1 ^ (state1 >> 7));
				state1 = state2;
				state2 = state3;
				state3 = state4;
				state4 = state5;
				state5 = (state5 ^ (state5 << 6)) ^ (t ^ (t << 13));

				l = ((state2 + state2 + 1) * state5);
			}
			{

				int t = (state1 ^ (state1 >> 7));
				state1 = state2;
				state2 = state3;
				state3 = state4;
				state4 = state5;
				state5 = (state5 ^ (state5 << 6)) ^ (t ^ (t << 13));

				r = ((state2 + state2 + 1) * state5);
			}

			longBuffer.put((((long) l) << 32) + r);
			longs++;
		}
		return numLongs - longBuffer.remaining();
	}

	@Override
	public final int read(DoubleBuffer doubleBuffer) {

		final int numDoubles = doubleBuffer.remaining();

		int doubles = 0;

		for (; doubles < numDoubles; doubles++) {

			if (!isOpen()) // check interruption status
				return doubles; // interrupt

			int l;
			int r;

			// ///////////////// GENERATE FUNCTION /////////////////////
			{

				int t = (state1 ^ (state1 >> 7));
				state1 = state2;
				state2 = state3;
				state3 = state4;
				state4 = state5;
				state5 = (state5 ^ (state5 << 6)) ^ (t ^ (t << 13));

				l = ((state2 + state2 + 1) * state5);
			}
			{

				int t = (state1 ^ (state1 >> 7));
				state1 = state2;
				state2 = state3;
				state3 = state4;
				state4 = state5;
				state5 = (state5 ^ (state5 << 6)) ^ (t ^ (t << 13));

				r = ((state2 + state2 + 1) * state5);
			}

			doubleBuffer.put(((((long) (l >>> 6)) << 27) + (r >>> 5))
					/ (double) (1L << 53));
		}

		return numDoubles - doubleBuffer.remaining() /* should be zero */;

	}

	@Override
	public final int nextInt() {

		int t = (state1 ^ (state1 >> 7));
		state1 = state2;
		state2 = state3;
		state3 = state4;
		state4 = state5;
		state5 = (state5 ^ (state5 << 6)) ^ (t ^ (t << 13));
		return (state2 + state2 + 1) * state5;
	}

	@Override
	public final float nextFloat() {

		int t = (state1 ^ (state1 >> 7));
		state1 = state2;
		state2 = state3;
		state3 = state4;
		state4 = state5;
		state5 = (state5 ^ (state5 << 6)) ^ (t ^ (t << 13));

		return ((((state2 + state2 + 1) * state5) >>> 8) / ((float) (1 << 24)));
	}

	@Override
	public final long nextLong() {
		int l;
		int r;

		// ///////////////// GENERATE FUNCTION /////////////////////
		{

			int t = (state1 ^ (state1 >> 7));
			state1 = state2;
			state2 = state3;
			state3 = state4;
			state4 = state5;
			state5 = (state5 ^ (state5 << 6)) ^ (t ^ (t << 13));

			l = ((state2 + state2 + 1) * state5);
		}
		{

			int t = (state1 ^ (state1 >> 7));
			state1 = state2;
			state2 = state3;
			state3 = state4;
			state4 = state5;
			state5 = (state5 ^ (state5 << 6)) ^ (t ^ (t << 13));

			r = ((state2 + state2 + 1) * state5);
		}

		return ((((long) l) << 32) + r);
	}

	@Override
	public final double nextDouble() {
		int l;
		int r;

		// ///////////////// GENERATE FUNCTION /////////////////////
		{

			int t = (state1 ^ (state1 >> 7));
			state1 = state2;
			state2 = state3;
			state3 = state4;
			state4 = state5;
			state5 = (state5 ^ (state5 << 6)) ^ (t ^ (t << 13));

			l = ((state2 + state2 + 1) * state5);
		}
		{

			int t = (state1 ^ (state1 >> 7));
			state1 = state2;
			state2 = state3;
			state3 = state4;
			state4 = state5;
			state5 = (state5 ^ (state5 << 6)) ^ (t ^ (t << 13));

			r = ((state2 + state2 + 1) * state5);
		}

		return ((((long) (l >>> 6)) << 27) + (r >>> 5)) / (double) (1L << 53);

	}

	private final int generate32() {
		int t = (state1 ^ (state1 >> 7));
		state1 = state2;
		state2 = state3;
		state3 = state4;
		state4 = state5;
		state5 = (state5 ^ (state5 << 6)) ^ (t ^ (t << 13));
		return (state2 + state2 + 1) * state5;
	}

	@Override
	public final String toString() {
		return PRNG.XOR_SHIFT.name();
	}

	@Override
	public final int hashCode() {
		if (!isOpen())
			return System.identityHashCode(this);

		int hashCode = 13;
		hashCode = 37 * hashCode + (int) (state1);
		hashCode = 37 * hashCode + (int) (state2);
		hashCode = 37 * hashCode + (int) (state3);
		hashCode = 37 * hashCode + (int) (state4);
		return 37 * hashCode + (int) (state5);

	}

	@Override
	public final boolean equals(Object obj) {
		if (obj == null)
			return false;

		if (!this.isOpen())
			return false;

		if (!(obj instanceof XORShift))
			return false;

		if (obj == this)
			return true;

		XORShift that = (XORShift) obj;

		if (!that.isOpen())
			return false;

		return this.hashCode() == that.hashCode();
	}

	@Override
	public final XORShift copy() {
		XORShift copy = (XORShift) new XORShift();
		copy.reseed((ByteBuffer) this.mark.clear());

		copy.state1 = this.state1;
		copy.state2 = this.state2;
		copy.state3 = this.state3;
		copy.state4 = this.state4;
		copy.state5 = this.state5;

		return copy;

	}

	@Override
	public final int minlen() {
		return INT_SIZE_BYTES;
	}
}
