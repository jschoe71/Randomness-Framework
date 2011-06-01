/*
 * Copyright 2005, Nick Galbreath -- nickg [at] modp [dot] com
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *   Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 *   Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.
 *
 *   Neither the name of the modp.com nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * This is the standard "new" BSD license:
 * http://www.opensource.org/licenses/bsd-license.php
 */

package org.randomness;

import java.nio.ByteBuffer;
import java.nio.DoubleBuffer;
import java.nio.FloatBuffer;
import java.nio.IntBuffer;
import java.nio.LongBuffer;

final class CellularAutomatonRule30 extends PseudorandomnessEngine {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	// the internal state
	private long w0;
	private long w1;
	private long w2;

	/**
	 * Default constructor. Probably uses current time to seed generator
	 */
	public CellularAutomatonRule30() {
		this.reset();
	}

	/**
	 * Set the seed using 3 long values.
	 * 
	 * The three 64-bit long value define the initial starting conditions and
	 * the bit values are layed out as a bit-string from left to right
	 * 
	 * <pre>
	 * w0-0 w0-1 .... w0-63 w1-0 w1-1 .... w1-63 w2-0 w2-1 ... w2-63
	 * </pre>
	 * 
	 * To get the clasical Rule 30 with "black dot" in the middle Use
	 * <code>(0L, 1L << 32, 0L)</code>
	 * 
	 * @param w0
	 *            bits 0-63
	 * @param w1
	 *            bits 64-127
	 * @param w2
	 *            bits 128-191
	 */

	protected final void instantiate(ByteBuffer seed) {
		final int BLOCKS = 3;
		final int BITS_PER_BLOCK = 64;

		// this loop can certainly be unrolled, and the use of array eliminated
		// however this isn't critical and this shows how to extend
		// the algorithm for more blocks
		// pack into array to simply algorithm below
		long input[] = { seed.getLong(), seed.getLong(), seed.getLong() };

		long output[] = new long[BLOCKS]; // tmp variable for holding state

		for (int j = 0; j < BLOCKS * BITS_PER_BLOCK; ++j) {
			int inputBlock = j / BITS_PER_BLOCK;
			int inputPos = j % BITS_PER_BLOCK;
			int outputBlock = j % BLOCKS;
			int outputPos = j / BLOCKS;

			// get the bit we are working on
			// if it's 0, nothing to do
			// if it's 1, set the appropriate bit
			// MAYBE: use table instead of shifting.
			if ((input[inputBlock] & (1L << inputPos)) != 0L) {
				output[outputBlock] |= (1L << outputPos);
			}
		}
		this.w0 = output[0];
		this.w1 = output[1];
		this.w2 = output[2];
	}

	private final int generate32() {
		int result = 0;
		long t0, t1, t2;

		// ROTATE LEFT foo = (foo << 1) | (foo >>> 63);
		// ROTATE RIGHT foo = (foo >> 1) | (foo << 63);
		for (int j = Integer.SIZE; j != 0; --j) {
			result = (result << 1) | (int) ((w0 >>> 32) & 1L);
			t0 = ((w2 >>> 1) | (w2 << 63)) ^ (w0 | w1);
			t2 = w1 ^ (w2 | ((w0 << 1) | (w0 >>> 63)));
			t1 = w0 ^ (w1 | w2);
			w0 = t0;
			w1 = t1;
			w2 = t2;
		}
		return result;
	}

	@Override
	public final int read(ByteBuffer buffer) {
		final int numBytes = buffer.remaining();

		int bytes = 0;

		for (; (numBytes - bytes) >= INT_SIZE_BYTES;) {

			if (shared && !isOpen()) {// check interruption status
				return bytes; // interrupt
			}

			// ///////////////// GENERATE FUNCTION /////////////////////
			int result = 0;
			long t0, t1, t2;

			// ROTATE LEFT foo = (foo << 1) | (foo >>> 63);
			// ROTATE RIGHT foo = (foo >> 1) | (foo << 63);
			for (int j = Integer.SIZE; j != 0; --j) {
				result = (result << 1) | (int) ((w0 >>> 32) & 1L);
				t0 = ((w2 >>> 1) | (w2 << 63)) ^ (w0 | w1);
				t2 = w1 ^ (w2 | ((w0 << 1) | (w0 >>> 63)));
				t1 = w0 ^ (w1 | w2);
				w0 = t0;
				w1 = t1;
				w2 = t2;
			}
			// ///////////////// GENERATE FUNCTION /////////////////////
			buffer.putInt(result);
			bytes += INT_SIZE_BYTES; // inc bytes
		}

		if (bytes < numBytes) { // put last bytes
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
			int result = 0;
			long t0, t1, t2;

			for (int j = Integer.SIZE; j != 0; --j) {
				result = (result << 1) | (int) ((w0 >>> 32) & 1L);
				t0 = ((w2 >>> 1) | (w2 << 63)) ^ (w0 | w1);
				t2 = w1 ^ (w2 | ((w0 << 1) | (w0 >>> 63)));
				t1 = w0 ^ (w1 | w2);
				w0 = t0;
				w1 = t1;
				w2 = t2;
			}
			// ///////////////// GENERATE FUNCTION /////////////////////

			intBuffer.put(result);
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
			int x = 0;
			long t0, t1, t2;

			for (int j = Integer.SIZE; j != 0; --j) {
				x = (x << 1) | (int) ((w0 >>> 32) & 1L);
				t0 = ((w2 >>> 1) | (w2 << 63)) ^ (w0 | w1);
				t2 = w1 ^ (w2 | ((w0 << 1) | (w0 >>> 63)));
				t1 = w0 ^ (w1 | w2);
				w0 = t0;
				w1 = t1;
				w2 = t2;
			}
			// ///////////////// GENERATE FUNCTION /////////////////////

			floatBuffer.put((x >>> 8) / ((float) (1 << 24)));
			floats++;
		}

		return numFloats - floatBuffer.remaining();

	}

	@Override
	public final int read(LongBuffer longBuffer) {
		final int numLongs = longBuffer.remaining();

		for (int longs = 0; longs < numLongs;) {

			if (shared && !isOpen()) // check interruption status
				return longs; // interrupt

			int l;
			int r;
			// ///////////////// GENERATE FUNCTION /////////////////////
			{
				int x = 0;
				long t0, t1, t2;

				for (int j = Integer.SIZE; j != 0; --j) {
					x = (x << 1) | (int) ((w0 >>> 32) & 1L);
					t0 = ((w2 >>> 1) | (w2 << 63)) ^ (w0 | w1);
					t2 = w1 ^ (w2 | ((w0 << 1) | (w0 >>> 63)));
					t1 = w0 ^ (w1 | w2);
					w0 = t0;
					w1 = t1;
					w2 = t2;
				}
				l = x;
			}
			// ///////////////// GENERATE FUNCTION /////////////////////
			{
				int x = 0;
				long t0, t1, t2;

				for (int j = Integer.SIZE; j != 0; --j) {
					x = (x << 1) | (int) ((w0 >>> 32) & 1L);
					t0 = ((w2 >>> 1) | (w2 << 63)) ^ (w0 | w1);
					t2 = w1 ^ (w2 | ((w0 << 1) | (w0 >>> 63)));
					t1 = w0 ^ (w1 | w2);
					w0 = t0;
					w1 = t1;
					w2 = t2;
				}
				r = x;
			}
			// ///////////////// GENERATE FUNCTION /////////////////////
			longBuffer.put((((long) l) << 32) + r);
			longs++;
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
				int x = 0;
				long t0, t1, t2;

				for (int j = Integer.SIZE; j != 0; --j) {
					x = (x << 1) | (int) ((w0 >>> 32) & 1L);
					t0 = ((w2 >>> 1) | (w2 << 63)) ^ (w0 | w1);
					t2 = w1 ^ (w2 | ((w0 << 1) | (w0 >>> 63)));
					t1 = w0 ^ (w1 | w2);
					w0 = t0;
					w1 = t1;
					w2 = t2;
				}
				l = x;
			}
			// ///////////////// GENERATE FUNCTION /////////////////////
			{
				int x = 0;
				long t0, t1, t2;

				for (int j = Integer.SIZE; j != 0; --j) {
					x = (x << 1) | (int) ((w0 >>> 32) & 1L);
					t0 = ((w2 >>> 1) | (w2 << 63)) ^ (w0 | w1);
					t2 = w1 ^ (w2 | ((w0 << 1) | (w0 >>> 63)));
					t1 = w0 ^ (w1 | w2);
					w0 = t0;
					w1 = t1;
					w2 = t2;
				}
				r = x;
			}
			// ///////////////// GENERATE FUNCTION /////////////////////
			doubleBuffer.put(((((long) (l >>> 6)) << 27) + (r >>> 5))
					/ (double) (1L << 53));
			doubles++;
		}

		return numDoubles - doubleBuffer.remaining() /* should be zero */;
	}

	@Override
	public final int nextInt() {
		int result = 0;
		long t0, t1, t2;

		for (int j = Integer.SIZE; j != 0; --j) {
			result = (result << 1) | (int) ((w0 >>> 32) & 1L);
			t0 = ((w2 >>> 1) | (w2 << 63)) ^ (w0 | w1);
			t2 = w1 ^ (w2 | ((w0 << 1) | (w0 >>> 63)));
			t1 = w0 ^ (w1 | w2);
			w0 = t0;
			w1 = t1;
			w2 = t2;
		}
		return result;
	}

	@Override
	public final float nextFloat() {
		int x = 0;
		long t0, t1, t2;

		for (int j = Integer.SIZE; j != 0; --j) {
			x = (x << 1) | (int) ((w0 >>> 32) & 1L);
			t0 = ((w2 >>> 1) | (w2 << 63)) ^ (w0 | w1);
			t2 = w1 ^ (w2 | ((w0 << 1) | (w0 >>> 63)));
			t1 = w0 ^ (w1 | w2);
			w0 = t0;
			w1 = t1;
			w2 = t2;
		}
		// ///////////////// GENERATE FUNCTION /////////////////////

		return ((x >>> 8) / ((float) (1 << 24)));
	}

	@Override
	public final long nextLong() {
		int l = 0;
		long t0, t1, t2;

		for (int j = Integer.SIZE; j != 0; --j) {
			l = (l << 1) | (int) ((w0 >>> 32) & 1L);
			t0 = ((w2 >>> 1) | (w2 << 63)) ^ (w0 | w1);
			t2 = w1 ^ (w2 | ((w0 << 1) | (w0 >>> 63)));
			t1 = w0 ^ (w1 | w2);
			w0 = t0;
			w1 = t1;
			w2 = t2;
		}

		int r = 0;

		for (int j = Integer.SIZE; j != 0; --j) {
			r = (r << 1) | (int) ((w0 >>> 32) & 1L);
			t0 = ((w2 >>> 1) | (w2 << 63)) ^ (w0 | w1);
			t2 = w1 ^ (w2 | ((w0 << 1) | (w0 >>> 63)));
			t1 = w0 ^ (w1 | w2);
			w0 = t0;
			w1 = t1;
			w2 = t2;
		}

		return (((long) l) << 32) + r;
	}

	@Override
	public final double nextDouble() {
		int l;
		int r;
		// ///////////////// GENERATE FUNCTION /////////////////////
		{
			int x = 0;
			long t0, t1, t2;

			for (int j = Integer.SIZE; j != 0; --j) {
				x = (x << 1) | (int) ((w0 >>> 32) & 1L);
				t0 = ((w2 >>> 1) | (w2 << 63)) ^ (w0 | w1);
				t2 = w1 ^ (w2 | ((w0 << 1) | (w0 >>> 63)));
				t1 = w0 ^ (w1 | w2);
				w0 = t0;
				w1 = t1;
				w2 = t2;
			}
			l = x;
		}
		// ///////////////// GENERATE FUNCTION /////////////////////
		{
			int x = 0;
			long t0, t1, t2;

			for (int j = Integer.SIZE; j != 0; --j) {
				x = (x << 1) | (int) ((w0 >>> 32) & 1L);
				t0 = ((w2 >>> 1) | (w2 << 63)) ^ (w0 | w1);
				t2 = w1 ^ (w2 | ((w0 << 1) | (w0 >>> 63)));
				t1 = w0 ^ (w1 | w2);
				w0 = t0;
				w1 = t1;
				w2 = t2;
			}
			r = x;
		}
		// ///////////////// GENERATE FUNCTION /////////////////////
		return (((((long) (l >>> 6)) << 27) + (r >>> 5)) / (double) (1L << 53));
	}

	@Override
	public final Pseudorandomness copy() {
		CellularAutomatonRule30 copy = new CellularAutomatonRule30();
		copy.reseed((ByteBuffer) this.mark.clear());

		copy.w0 = this.w0;
		copy.w1 = this.w1;
		copy.w2 = this.w2;

		return copy;
	}

	@Override
	public final int hashCode() {
		if (!isOpen())
			return System.identityHashCode(this);

		int hashCode = 19;
		hashCode = 31 * hashCode + (int) (w0 ^ (w0 >>> 32));
		hashCode = 31 * hashCode + (int) (w1 ^ (w1 >>> 32));
		return 31 * hashCode + (int) (w2 ^ (w2 >>> 32));

	}

	@Override
	public final boolean equals(Object obj) {

		if (obj == null || !(obj instanceof CellularAutomatonRule30))
			return false;

		if (!this.isOpen())
			return false;

		if (obj == this)
			return true;

		CellularAutomatonRule30 that = (CellularAutomatonRule30) obj;

		if (!that.isOpen())
			return false;

		return (this.w0 == that.w0) && (this.w1 == that.w1)
				&& (this.w2 == that.w2);
	}

	@Override
	public final String toString() {
		return PRNG.CELLULAR_AUTOMATON_192_RULE_30.name();
	}

	@Override
	public final int minlen() {
		return INT_SIZE_BYTES;

	}
}
