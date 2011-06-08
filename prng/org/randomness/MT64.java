/*
 * Copyright 2005, Nick Galbreath -- nickg [at] modp [dot] com
 * Adopted to randomness framework by Anton Kabysh. 
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
 * 
 * Portions may also be
 * Copyright (C) 2004, Makoto Matsumoto and Takuji Nishimura,
 * All rights reserved.
 * (and covered under the BSD license)
 * See http://www.math.sci.hiroshima-u.ac.jp/~m-mat/MT/VERSIONS/C-LANG/mt19937-64.c
 */
package org.randomness;

import java.nio.ByteBuffer;
import java.nio.DoubleBuffer;
import java.nio.FloatBuffer;
import java.nio.IntBuffer;
import java.nio.LongBuffer;
import java.nio.channels.NonReadableChannelException;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.ReentrantLock;

/**
 * 
 * @author Anton Kabysh (randomness framework adaptation)
 * @author Nick Galbreath
 * 
 */
final class MT64 extends PseudorandomnessEngine implements Engine.MT {
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	private static final int N = 312;

	private static final int M = 156;

	private static final long MATRIX_A = 0xB5026F5AA96619E9L;

	/**
	 * Mask: Most significant 33 bits
	 */
	private static final long UM = 0xFFFFFFFF80000000L;

	/**
	 * Mask: Least significant 31 bits
	 */
	private static final long LM = 0x7FFFFFFFL;

	private static final long[] mag01 = { 0L, MATRIX_A };

	private long[] mt = new long[N];

	private int mti = N + 1;

	/**
         * 
         */
	public MT64() {
		this.reset();
	}

	/**
	 * Initalize the pseudo random number generator with 32-bits.
	 */
	private final void initGenRandom(final long seed) {
		mt[0] = seed;
		for (mti = 1; mti < N; mti++) {
			mt[mti] = (6364136223846793005L * (mt[mti - 1] ^ (mt[mti - 1] >>> 62)) + mti);
		}
	}

	@Override
	protected final void instantiate(ByteBuffer seed) {
		// ////////////////// INSTANTIATE FUNCTION ////////////////////////
		// convert seed bytes to long array
		LongBuffer longBuffer = seed.asLongBuffer();
		long[] array = new long[longBuffer.remaining()];
		longBuffer.get(array);

		initGenRandom(19650218L);
		int i = 1;
		int j = 0;
		int k = (N > array.length ? N : array.length);
		for (; k != 0; k--) {
			mt[i] = (mt[i] ^ ((mt[i - 1] ^ (mt[i - 1] >>> 62)) * 3935559000370003845L))
					+ array[j] + j;
			i++;
			j++;
			if (i >= N) {
				mt[0] = mt[N - 1];
				i = 1;
			}
			if (j >= array.length)
				j = 0;
		}
		for (k = N - 1; k != 0; k--) {
			mt[i] = (mt[i] ^ ((mt[i - 1] ^ (mt[i - 1] >>> 62)) * 2862933555777941757L))
					- i;
			i++;
			if (i >= N) {
				mt[0] = mt[N - 1];
				i = 1;
			}
		}

		mt[0] = 1L << 63; /* MSB is 1; assuring non-zero initial array */
		// ////////////////// INSTANTIATE FUNCTION ////////////////////////
		// /////////////////// GENERATE FUNCTION ///////////////////////////
		i = 0;
		long x;
		if (mti >= N) { /* generate NN words at one time */

			for (i = 0; i < N - M; i++) {
				x = (mt[i] & UM) | (mt[i + 1] & LM);
				mt[i] = mt[i + M] ^ (x >>> 1) ^ mag01[(int) (x & 1L)];
			}
			for (; i < N - 1; i++) {
				x = (mt[i] & UM) | (mt[i + 1] & LM);
				mt[i] = mt[i + (M - N)] ^ (x >>> 1) ^ mag01[(int) (x & 1L)];
			}
			x = (mt[N - 1] & UM) | (mt[0] & LM);
			mt[N - 1] = mt[M - 1] ^ (x >>> 1) ^ mag01[(int) (x & 1L)];

			mti = 0;
		}
		// /////////////////// GENERATE FUNCTION ///////////////////////////
	}

	private int generate32() {
		int i;
		long x;

		if (mti >= N) { /* generate NN words at one time */

			for (i = 0; i < N - M; i++) {
				x = (mt[i] & UM) | (mt[i + 1] & LM);
				mt[i] = mt[i + M] ^ (x >>> 1) ^ mag01[(int) (x & 1L)];
			}
			for (; i < N - 1; i++) {
				x = (mt[i] & UM) | (mt[i + 1] & LM);
				mt[i] = mt[i + (M - N)] ^ (x >>> 1) ^ mag01[(int) (x & 1L)];
			}
			x = (mt[N - 1] & UM) | (mt[0] & LM);
			mt[N - 1] = mt[M - 1] ^ (x >>> 1) ^ mag01[(int) (x & 1L)];

			mti = 0;
		}

		x = mt[mti++];

		x ^= (x >>> 29) & 0x5555555555555555L;
		x ^= (x << 17) & 0x71D67FFFEDA60000L;
		x ^= (x << 37) & 0xFFF7EEE000000000L;
		x ^= (x >>> 43);

		return (int) (x >>> 32);
	}

	private long generate64() {
		int i;
		long x;
		if (mti >= N) { /* generate NN words at one time */

			for (i = 0; i < N - M; i++) {
				x = (mt[i] & UM) | (mt[i + 1] & LM);
				mt[i] = mt[i + M] ^ (x >>> 1) ^ mag01[(int) (x & 1L)];
			}
			for (; i < N - 1; i++) {
				x = (mt[i] & UM) | (mt[i + 1] & LM);
				mt[i] = mt[i + (M - N)] ^ (x >>> 1) ^ mag01[(int) (x & 1L)];
			}
			x = (mt[N - 1] & UM) | (mt[0] & LM);
			mt[N - 1] = mt[M - 1] ^ (x >>> 1) ^ mag01[(int) (x & 1L)];

			mti = 0;
		}

		x = mt[mti++];

		x ^= (x >>> 29) & 0x5555555555555555L;
		x ^= (x << 17) & 0x71D67FFFEDA60000L;
		x ^= (x << 37) & 0xFFF7EEE000000000L;
		x ^= (x >>> 43);

		return x;
	}

	@Override
	public final int read(byte[] bytes) {
		int i = 0;
		final int iEnd = bytes.length - 7;
		while (i < iEnd) {

			if (!isOpen()) // check interruption status
				return i;

			final long random = generate64();
			bytes[i] = (byte) (random & 0xff);
			bytes[i + 1] = (byte) ((random >> 8) & 0xff);
			bytes[i + 2] = (byte) ((random >> 16) & 0xff);
			bytes[i + 3] = (byte) ((random >> 24) & 0xff);
			bytes[i + 4] = (byte) ((random >> 32) & 0xff);
			bytes[i + 5] = (byte) ((random >> 40) & 0xff);
			bytes[i + 6] = (byte) ((random >> 48) & 0xff);
			bytes[i + 7] = (byte) ((random >> 56) & 0xff);

			i += 8;
		}

		long random = generate64();
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

		for (; (numBytes - bytes) >= LONG_SIZE_BYTES;) {

			if (!isOpen()) // check interruption status
				return bytes; // interrupt

			// ///////////////// GENERATE FUNCTION /////////////////////
			int i;
			long x;
			if (mti >= N) { /* generate NN words at one time */

				for (i = 0; i < N - M; i++) {
					x = (mt[i] & UM) | (mt[i + 1] & LM);
					mt[i] = mt[i + M] ^ (x >>> 1) ^ mag01[(int) (x & 1L)];
				}
				for (; i < N - 1; i++) {
					x = (mt[i] & UM) | (mt[i + 1] & LM);
					mt[i] = mt[i + (M - N)] ^ (x >>> 1) ^ mag01[(int) (x & 1L)];
				}
				x = (mt[N - 1] & UM) | (mt[0] & LM);
				mt[N - 1] = mt[M - 1] ^ (x >>> 1) ^ mag01[(int) (x & 1L)];

				mti = 0;

				// //////////////// BLOCK MODE ///////////////////////////////
				if ((numBytes - bytes) >= (LONG_SIZE_BYTES * N)) {

					for (; mti < N;) {
						x = mt[mti++];
						x ^= (x >>> 29) & 0x5555555555555555L;
						x ^= (x << 17) & 0x71D67FFFEDA60000L;
						x ^= (x << 37) & 0xFFF7EEE000000000L;
						x ^= (x >>> 43);
						buffer.putLong(x);

						x = mt[mti++];
						x ^= (x >>> 29) & 0x5555555555555555L;
						x ^= (x << 17) & 0x71D67FFFEDA60000L;
						x ^= (x << 37) & 0xFFF7EEE000000000L;
						x ^= (x >>> 43);
						buffer.putLong(x);

						x = mt[mti++];
						x ^= (x >>> 29) & 0x5555555555555555L;
						x ^= (x << 17) & 0x71D67FFFEDA60000L;
						x ^= (x << 37) & 0xFFF7EEE000000000L;
						x ^= (x >>> 43);
						buffer.putLong(x);

						x = mt[mti++];
						x ^= (x >>> 29) & 0x5555555555555555L;
						x ^= (x << 17) & 0x71D67FFFEDA60000L;
						x ^= (x << 37) & 0xFFF7EEE000000000L;
						x ^= (x >>> 43);
						buffer.putLong(x);

					}

					bytes += LONG_SIZE_BYTES * N; // inc bytes
					continue;
				}
				// //////////////// BLOCK MODE ///////////////////////////////
			}

			x = mt[mti++];
			x ^= (x >>> 29) & 0x5555555555555555L;
			x ^= (x << 17) & 0x71D67FFFEDA60000L;
			x ^= (x << 37) & 0xFFF7EEE000000000L;
			x ^= (x >>> 43);

			buffer.putLong(x);
			bytes += LONG_SIZE_BYTES; // inc bytes
		}

		// transfer additional bytes
		if ((numBytes - bytes) > 0) {
			long rnd = generate64();
			// put last bytes

			for (int n = numBytes - bytes; n-- > 0; bytes++)
				buffer.put((byte) (rnd >>> (Byte.SIZE * n)));
		}

		return numBytes - buffer.remaining() /* should be zero */;

	}

	@Override
	public final int read(LongBuffer longBuffer) {
		final int numLongs = longBuffer.remaining();

		final boolean hasBlocks = longBuffer.remaining() >= N;
		long[] words = hasBlocks ? new long[N] : null;

		for (int longs = 0; longs < numLongs;) {

			if (!isOpen()) // check interruption status
				return longs; // interrupt

			// ///////////////// GENERATE FUNCTION /////////////////////
			long x;

			if (mti >= N) { /* generate NN words at one time */
				int i;
				for (i = 0; i < N - M; i++) {
					x = (mt[i] & UM) | (mt[i + 1] & LM);
					mt[i] = mt[i + M] ^ (x >>> 1) ^ mag01[(int) (x & 1L)];
				}
				for (; i < N - 1; i++) {
					x = (mt[i] & UM) | (mt[i + 1] & LM);
					mt[i] = mt[i + (M - N)] ^ (x >>> 1) ^ mag01[(int) (x & 1L)];
				}
				x = (mt[N - 1] & UM) | (mt[0] & LM);
				mt[N - 1] = mt[M - 1] ^ (x >>> 1) ^ mag01[(int) (x & 1L)];

				mti = 0;

				// //////////////// BLOCK MODE ///////////////////////////////
				if (hasBlocks)
					if (longBuffer.remaining() >= N) {

						for (; mti < N;) {

							x = mt[mti];
							x ^= (x >>> 29) & 0x5555555555555555L;
							x ^= (x << 17) & 0x71D67FFFEDA60000L;
							x ^= (x << 37) & 0xFFF7EEE000000000L;
							x ^= (x >>> 43);
							words[mti++] = x;

							x = mt[mti];
							x ^= (x >>> 29) & 0x5555555555555555L;
							x ^= (x << 17) & 0x71D67FFFEDA60000L;
							x ^= (x << 37) & 0xFFF7EEE000000000L;
							x ^= (x >>> 43);
							words[mti++] = x;

							x = mt[mti];
							x ^= (x >>> 29) & 0x5555555555555555L;
							x ^= (x << 17) & 0x71D67FFFEDA60000L;
							x ^= (x << 37) & 0xFFF7EEE000000000L;
							x ^= (x >>> 43);
							words[mti++] = x;

							x = mt[mti];
							x ^= (x >>> 29) & 0x5555555555555555L;
							x ^= (x << 17) & 0x71D67FFFEDA60000L;
							x ^= (x << 37) & 0xFFF7EEE000000000L;
							x ^= (x >>> 43);
							words[mti++] = x;

							x = mt[mti];
							x ^= (x >>> 29) & 0x5555555555555555L;
							x ^= (x << 17) & 0x71D67FFFEDA60000L;
							x ^= (x << 37) & 0xFFF7EEE000000000L;
							x ^= (x >>> 43);
							words[mti++] = x;

							x = mt[mti];
							x ^= (x >>> 29) & 0x5555555555555555L;
							x ^= (x << 17) & 0x71D67FFFEDA60000L;
							x ^= (x << 37) & 0xFFF7EEE000000000L;
							x ^= (x >>> 43);
							words[mti++] = x;

							x = mt[mti];
							x ^= (x >>> 29) & 0x5555555555555555L;
							x ^= (x << 17) & 0x71D67FFFEDA60000L;
							x ^= (x << 37) & 0xFFF7EEE000000000L;
							x ^= (x >>> 43);
							words[mti++] = x;

							x = mt[mti];
							x ^= (x >>> 29) & 0x5555555555555555L;
							x ^= (x << 17) & 0x71D67FFFEDA60000L;
							x ^= (x << 37) & 0xFFF7EEE000000000L;
							x ^= (x >>> 43);
							words[mti++] = x;

						}
						longBuffer.put(words);
						longs += N;
						continue;
					}
				// //////////////// BLOCK MODE ///////////////////////////////

			}

			x = mt[mti++];

			x ^= (x >>> 29) & 0x5555555555555555L;
			x ^= (x << 17) & 0x71D67FFFEDA60000L;
			x ^= (x << 37) & 0xFFF7EEE000000000L;
			x ^= (x >>> 43);
			// ///////////////// GENERATE FUNCTION /////////////////////

			longBuffer.put(x);
			longs++;
		}

		return numLongs - longBuffer.remaining() /* should be zero */;
	}

	@Override
	public final int read(DoubleBuffer doubleBuffer) {

		final int numDoubles = doubleBuffer.remaining();

		int doubles = 0;
		for (; doubles < numDoubles;) {

			if (!isOpen()) // check interruption status
				return doubles; // interrupt

			// ///////////////// GENERATE FUNCTION /////////////////////
			int i;
			long x;
			if (mti >= N) { /* generate NN words at one time */

				for (i = 0; i < N - M; i++) {
					x = (mt[i] & UM) | (mt[i + 1] & LM);
					mt[i] = mt[i + M] ^ (x >>> 1) ^ mag01[(int) (x & 1L)];
				}
				for (; i < N - 1; i++) {
					x = (mt[i] & UM) | (mt[i + 1] & LM);
					mt[i] = mt[i + (M - N)] ^ (x >>> 1) ^ mag01[(int) (x & 1L)];
				}
				x = (mt[N - 1] & UM) | (mt[0] & LM);
				mt[N - 1] = mt[M - 1] ^ (x >>> 1) ^ mag01[(int) (x & 1L)];

				mti = 0;

				// //////////////// BLOCK MODE ///////////////////////////////
				if (doubleBuffer.remaining() >= N) {

					for (; mti < N;) {

						x = mt[mti++];
						x ^= (x >>> 29) & 0x5555555555555555L;
						x ^= (x << 17) & 0x71D67FFFEDA60000L;
						x ^= (x << 37) & 0xFFF7EEE000000000L;
						x ^= (x >>> 43);
						doubleBuffer.put(((x) >>> 11) / (double) (1L << 53));

						x = mt[mti++];
						x ^= (x >>> 29) & 0x5555555555555555L;
						x ^= (x << 17) & 0x71D67FFFEDA60000L;
						x ^= (x << 37) & 0xFFF7EEE000000000L;
						x ^= (x >>> 43);
						doubleBuffer.put(((x) >>> 11) / (double) (1L << 53));

						x = mt[mti++];
						x ^= (x >>> 29) & 0x5555555555555555L;
						x ^= (x << 17) & 0x71D67FFFEDA60000L;
						x ^= (x << 37) & 0xFFF7EEE000000000L;
						x ^= (x >>> 43);
						doubleBuffer.put(((x) >>> 11) / (double) (1L << 53));

						x = mt[mti++];
						x ^= (x >>> 29) & 0x5555555555555555L;
						x ^= (x << 17) & 0x71D67FFFEDA60000L;
						x ^= (x << 37) & 0xFFF7EEE000000000L;
						x ^= (x >>> 43);
						doubleBuffer.put(((x) >>> 11) / (double) (1L << 53));

					}
					doubles += N;
					continue;
					// //////////////// BLOCK MODE // ////////////////
				}
			}

			x = mt[mti++];

			x ^= (x >>> 29) & 0x5555555555555555L;
			x ^= (x << 17) & 0x71D67FFFEDA60000L;
			x ^= (x << 37) & 0xFFF7EEE000000000L;
			x ^= (x >>> 43);
			// ///////////////// GENERATE FUNCTION /////////////////////

			doubleBuffer.put(((x) >>> 11) / (double) (1L << 53));
			doubles++;
		}

		return numDoubles - doubleBuffer.remaining() /* should be zero */;
	}

	@Override
	public final int read(IntBuffer intBuffer) {
		final int numInts = intBuffer.remaining();

		int longs = 0;

		final int numLongs = numInts / (LONG_SIZE_BYTES / INT_SIZE_BYTES);

		for (; longs < numLongs;) {

			if (!isOpen()) // check interruption status
				return longs * (LONG_SIZE_BYTES / INT_SIZE_BYTES); // interrupt

			// ///////////////// GENERATE FUNCTION /////////////////////
			int i;
			long x;
			if (mti >= N) { /* generate NN words at one time */

				for (i = 0; i < N - M; i++) {
					x = (mt[i] & UM) | (mt[i + 1] & LM);
					mt[i] = mt[i + M] ^ (x >>> 1) ^ mag01[(int) (x & 1L)];
				}
				for (; i < N - 1; i++) {
					x = (mt[i] & UM) | (mt[i + 1] & LM);
					mt[i] = mt[i + (M - N)] ^ (x >>> 1) ^ mag01[(int) (x & 1L)];
				}
				x = (mt[N - 1] & UM) | (mt[0] & LM);
				mt[N - 1] = mt[M - 1] ^ (x >>> 1) ^ mag01[(int) (x & 1L)];

				mti = 0;

				if (intBuffer.remaining() >= 624) {

					for (; mti < N;) {

						x = mt[mti++];
						x ^= (x >>> 29) & 0x5555555555555555L;
						x ^= (x << 17) & 0x71D67FFFEDA60000L;
						x ^= (x << 37) & 0xFFF7EEE000000000L;
						x ^= (x >>> 43);
						intBuffer.put((int) (x >>> Integer.SIZE));
						intBuffer.put((int) x);

						x = mt[mti++];
						x ^= (x >>> 29) & 0x5555555555555555L;
						x ^= (x << 17) & 0x71D67FFFEDA60000L;
						x ^= (x << 37) & 0xFFF7EEE000000000L;
						x ^= (x >>> 43);
						intBuffer.put((int) (x >>> Integer.SIZE));
						intBuffer.put((int) x);

						x = mt[mti++];
						x ^= (x >>> 29) & 0x5555555555555555L;
						x ^= (x << 17) & 0x71D67FFFEDA60000L;
						x ^= (x << 37) & 0xFFF7EEE000000000L;
						x ^= (x >>> 43);
						intBuffer.put((int) (x >>> Integer.SIZE));
						intBuffer.put((int) x);

						x = mt[mti++];
						x ^= (x >>> 29) & 0x5555555555555555L;
						x ^= (x << 17) & 0x71D67FFFEDA60000L;
						x ^= (x << 37) & 0xFFF7EEE000000000L;
						x ^= (x >>> 43);
						intBuffer.put((int) (x >>> Integer.SIZE));
						intBuffer.put((int) x);

					}
					longs += N;
					continue;
				}
			}

			x = mt[mti++];

			x ^= (x >>> 29) & 0x5555555555555555L;
			x ^= (x << 17) & 0x71D67FFFEDA60000L;
			x ^= (x << 37) & 0xFFF7EEE000000000L;
			x ^= (x >>> 43);
			// ///////////////// GENERATE FUNCTION /////////////////////
			intBuffer.put((int) (x >>> Integer.SIZE));
			intBuffer.put((int) x);
			longs++;
		}

		// if num is not odd, add last one
		for (; intBuffer.hasRemaining();) {
			intBuffer.put(generate32());
		}

		return numInts - intBuffer.remaining();
	}

	@Override
	public int read(FloatBuffer floatBuffer) {
		final int numFloats = floatBuffer.remaining();

		int longs = 0;

		final int numLongs = numFloats / (LONG_SIZE_BYTES / FLOAT_SIZE_BYTES);

		for (; longs < numLongs;) {

			if (!isOpen()) // check interruption status
				return longs * (LONG_SIZE_BYTES / FLOAT_SIZE_BYTES); // interrupt

			// ///////////////// GENERATE FUNCTION /////////////////////
			int i;
			long x;
			if (mti >= N) { /* generate NN words at one time */

				for (i = 0; i < N - M; i++) {
					x = (mt[i] & UM) | (mt[i + 1] & LM);
					mt[i] = mt[i + M] ^ (x >>> 1) ^ mag01[(int) (x & 1L)];
				}
				for (; i < N - 1; i++) {
					x = (mt[i] & UM) | (mt[i + 1] & LM);
					mt[i] = mt[i + (M - N)] ^ (x >>> 1) ^ mag01[(int) (x & 1L)];
				}
				x = (mt[N - 1] & UM) | (mt[0] & LM);
				mt[N - 1] = mt[M - 1] ^ (x >>> 1) ^ mag01[(int) (x & 1L)];

				mti = 0;

				if (floatBuffer.remaining() >= 624) {

					for (; mti < N;) {

						x = mt[mti++];
						x ^= (x >>> 29) & 0x5555555555555555L;
						x ^= (x << 17) & 0x71D67FFFEDA60000L;
						x ^= (x << 37) & 0xFFF7EEE000000000L;
						x ^= (x >>> 43);
						floatBuffer.put((((int) (x >>> Integer.SIZE)) >>> 8)
								/ ((float) (1 << 24)));
						floatBuffer
								.put((((int) x) >>> 8) / ((float) (1 << 24)));

						x = mt[mti++];
						x ^= (x >>> 29) & 0x5555555555555555L;
						x ^= (x << 17) & 0x71D67FFFEDA60000L;
						x ^= (x << 37) & 0xFFF7EEE000000000L;
						x ^= (x >>> 43);
						floatBuffer.put((((int) (x >>> Integer.SIZE)) >>> 8)
								/ ((float) (1 << 24)));
						floatBuffer
								.put((((int) x) >>> 8) / ((float) (1 << 24)));

						x = mt[mti++];
						x ^= (x >>> 29) & 0x5555555555555555L;
						x ^= (x << 17) & 0x71D67FFFEDA60000L;
						x ^= (x << 37) & 0xFFF7EEE000000000L;
						x ^= (x >>> 43);
						floatBuffer.put((((int) (x >>> Integer.SIZE)) >>> 8)
								/ ((float) (1 << 24)));
						floatBuffer
								.put((((int) x) >>> 8) / ((float) (1 << 24)));

						x = mt[mti++];
						x ^= (x >>> 29) & 0x5555555555555555L;
						x ^= (x << 17) & 0x71D67FFFEDA60000L;
						x ^= (x << 37) & 0xFFF7EEE000000000L;
						x ^= (x >>> 43);
						floatBuffer.put((((int) (x >>> Integer.SIZE)) >>> 8)
								/ ((float) (1 << 24)));
						floatBuffer
								.put((((int) x) >>> 8) / ((float) (1 << 24)));

					}
					longs += N;
					continue;
				}
			}

			x = mt[mti++];

			x ^= (x >>> 29) & 0x5555555555555555L;
			x ^= (x << 17) & 0x71D67FFFEDA60000L;
			x ^= (x << 37) & 0xFFF7EEE000000000L;
			x ^= (x >>> 43);
			// ///////////////// GENERATE FUNCTION /////////////////////
			floatBuffer.put((((int) (x >>> Integer.SIZE)) >>> 8)
					/ ((float) (1 << 24)));
			floatBuffer.put((((int) x) >>> 8) / ((float) (1 << 24)));

			longs++;
		}

		// if num is not odd, add last one
		for (; floatBuffer.hasRemaining();) {
			floatBuffer.put((((int) generate32()) >>> 8) / ((float) (1 << 24)));
		}

		return numFloats - floatBuffer.remaining();
	}

	@Override
	public final int nextInt() {
		int i;
		long x;

		if (mti >= N) { /* generate NN words at one time */

			for (i = 0; i < N - M; i++) {
				x = (mt[i] & UM) | (mt[i + 1] & LM);
				mt[i] = mt[i + M] ^ (x >>> 1) ^ mag01[(int) (x & 1L)];
			}
			for (; i < N - 1; i++) {
				x = (mt[i] & UM) | (mt[i + 1] & LM);
				mt[i] = mt[i + (M - N)] ^ (x >>> 1) ^ mag01[(int) (x & 1L)];
			}
			x = (mt[N - 1] & UM) | (mt[0] & LM);
			mt[N - 1] = mt[M - 1] ^ (x >>> 1) ^ mag01[(int) (x & 1L)];

			mti = 0;
		}

		x = mt[mti++];

		x ^= (x >>> 29) & 0x5555555555555555L;
		x ^= (x << 17) & 0x71D67FFFEDA60000L;
		x ^= (x << 37) & 0xFFF7EEE000000000L;
		x ^= (x >>> 43);

		return (int) (x >>> 32);
	}

	@Override
	public float nextFloat() {
		int i;
		long x;

		if (mti >= N) { /* generate NN words at one time */

			for (i = 0; i < N - M; i++) {
				x = (mt[i] & UM) | (mt[i + 1] & LM);
				mt[i] = mt[i + M] ^ (x >>> 1) ^ mag01[(int) (x & 1L)];
			}
			for (; i < N - 1; i++) {
				x = (mt[i] & UM) | (mt[i + 1] & LM);
				mt[i] = mt[i + (M - N)] ^ (x >>> 1) ^ mag01[(int) (x & 1L)];
			}
			x = (mt[N - 1] & UM) | (mt[0] & LM);
			mt[N - 1] = mt[M - 1] ^ (x >>> 1) ^ mag01[(int) (x & 1L)];

			mti = 0;
		}

		x = mt[mti++];

		x ^= (x >>> 29) & 0x5555555555555555L;
		x ^= (x << 17) & 0x71D67FFFEDA60000L;
		x ^= (x << 37) & 0xFFF7EEE000000000L;
		x ^= (x >>> 43);

		return (((int) (x >>> Integer.SIZE)) >>> 8) / ((float) (1 << 24));
	}

	@Override
	public final long nextLong() {

		long x;
		if (mti >= N) { /* generate NN words at one time */
			int i;

			for (i = 0; i < N - M; i++) {
				x = (mt[i] & UM) | (mt[i + 1] & LM);
				mt[i] = mt[i + M] ^ (x >>> 1) ^ mag01[(int) (x & 1L)];
			}
			for (; i < N - 1; i++) {
				x = (mt[i] & UM) | (mt[i + 1] & LM);
				mt[i] = mt[i + (M - N)] ^ (x >>> 1) ^ mag01[(int) (x & 1L)];
			}
			x = (mt[N - 1] & UM) | (mt[0] & LM);
			mt[N - 1] = mt[M - 1] ^ (x >>> 1) ^ mag01[(int) (x & 1L)];

			mti = 0;
		}

		x = mt[mti++];

		x ^= (x >>> 29) & 0x5555555555555555L;
		x ^= (x << 17) & 0x71D67FFFEDA60000L;
		x ^= (x << 37) & 0xFFF7EEE000000000L;
		x ^= (x >>> 43);

		return x;
	}

	@Override
	public final double nextDouble() {
		int i;
		long x;
		if (mti >= N) { /* generate NN words at one time */

			for (i = 0; i < N - M; i++) {
				x = (mt[i] & UM) | (mt[i + 1] & LM);
				mt[i] = mt[i + M] ^ (x >>> 1) ^ mag01[(int) (x & 1L)];
			}
			for (; i < N - 1; i++) {
				x = (mt[i] & UM) | (mt[i + 1] & LM);
				mt[i] = mt[i + (M - N)] ^ (x >>> 1) ^ mag01[(int) (x & 1L)];
			}
			x = (mt[N - 1] & UM) | (mt[0] & LM);
			mt[N - 1] = mt[M - 1] ^ (x >>> 1) ^ mag01[(int) (x & 1L)];

			mti = 0;
		}

		x = mt[mti++];

		x ^= (x >>> 29) & 0x5555555555555555L;
		x ^= (x << 17) & 0x71D67FFFEDA60000L;
		x ^= (x << 37) & 0xFFF7EEE000000000L;
		x ^= (x >>> 43);

		return ((x) >>> 11) / (double) (1L << 53);
	}

	@Override
	public final Pseudorandomness copy() {
		MT64 copy = new MT64();
		copy.reseed((ByteBuffer) this.mark.clear());

		copy.mti = this.mti;
		System.arraycopy(this.mt, 0, copy.mt, 0, this.mt.length);

		return copy;
	}

	@Override
	public final int hashCode() {
		if (!isOpen())
			return System.identityHashCode(this);

		int hash = 17;

		hash = 37 * hash + Arrays.hashCode(mag01);
		hash = 37 * hash + Arrays.hashCode(mt);
		return 31 * hash + mti;
	}

	@Override
	public final boolean equals(Object obj) {
		if (obj == null)
			return false;

		if (!this.isOpen())
			return false;

		if (!(obj instanceof Pseudorandomness))
			return false;

		if (!((Pseudorandomness) obj).isOpen())
			return false;

		if (obj == this)
			return true;

		if (!(obj instanceof Engine.MT))
			return false;

		Engine.MT other = (Engine.MT) obj;

		if (this.mti() != other.mti())
			return false;

		if (!(other.mag01() instanceof long[]))
			return false; // possibly MT32.

		final long mag01[] = this.mag01();
		final long mag02[] = (long[]) other.mag01();

		for (int x = 0; x < mag01.length; x++)
			if (mag01[x] != mag02[x])
				return false;

		if (!(other.mt() instanceof long[]))
			return false; // possibly MT32.

		final long mt1[] = this.mt();
		final long mt2[] = (long[]) other.mt();

		for (int x = 0; x < mt1.length; x++)
			if (mt1[x] != mt2[x])
				return false;

		return true;
	}

	@Override
	public final String toString() {
		return PRNG.MT64.name();
	}

	@Override
	public final int mti() {
		return mti;
	}

	@Override
	public final long[] mt() {
		return mt;
	}

	@Override
	public final long[] mag01() {
		return mag01;
	}

	@Override
	public final int minlen() {
		return LONG_SIZE_BYTES;
	}

	/**
	 * Shared wrapper around MT64
	 * 
	 * @author Anton Kabysh
	 * 
	 */
	final class Shared extends Pseudorandomness implements Engine.MT {
		/**
		 * 
		 */
		private static final long serialVersionUID = 1L;
		private final AtomicInteger idx = new AtomicInteger(0);
		private final ReentrantLock lock = new ReentrantLock();
		private final MT64 _this = MT64.this;

		public Shared() {
			idx.set(_this.mti);
		}

		// ///////////////////////////////////////////////////////////
		// /////////////// PRNG MECHANISMS ///////////////////////////
		// ///////////////////////////////////////////////////////////

		protected int seedlen() {
			return MT64.this.seedlen();
		};

		@Override
		public long[] mag01() {
			return _this.mag01();
		}

		@Override
		public long[] mt() {
			return _this.mt();
		}

		@Override
		public int mti() {
			return _this.mti();
		}

		@Override
		public final void reset() {
			try {
				lock.lock();

				nextInt = nextLong = true; // clear intermediate state
				_this.reset();
				idx.set(_this.mti);

			} finally {
				lock.unlock();
			}
		}

		@Override
		public final Pseudorandomness reseed(ByteBuffer seed) {
			try {
				lock.lock();

				nextInt = nextLong = true; // clear intermediate state
				_this.reseed(seed);
				idx.set(_this.mti);

			} finally {
				lock.unlock();
			}

			return this;
		}

		@Override
		public final int tryRead(ByteBuffer buffer) {
			if (lock.isLocked())
				return -1;

			return this.read(buffer);
		}

		@Override
		public final boolean isOpen() {
			return _this.isOpen();
		}

		@Override
		public final void close() {
			_this.close();
		}

		@Override
		public final int minlen() {
			return _this.minlen();
		}

		@Override
		protected final ByteBuffer newBuffer(int bufferSize) {
			return _this.newBuffer(bufferSize);
		}

		@Override
		protected final byte[] getEntropyInput(int minEntropy) {
			return _this.getEntropyInput(minEntropy);
		}

		// ///////////////////////////////////////////////////////////
		// /////////////// PRNG GENERATE FUNCTIONS ///////////////////
		// ///////////////////////////////////////////////////////////

		private final void begin() {
			if (!isOpen())
				throw new NonReadableChannelException();

			lock.lock();
			_this.mti = acquireCounter();
			nextInt = nextLong = true; // clear intermediate state
		}

		private final void end() {
			releaseCounter(_this.mti); // restore counter to global state
			lock.unlock();

		}

		@Override
		public int read(byte[] bytes) {

			int read = 0;

			try {
				begin();

				read = _this.read(bytes);

			} finally {
				end();
			}

			return read;
		}

		@Override
		public final int read(ByteBuffer buffer) {

			final int numBytes = buffer.remaining();

			try {
				begin();

				_this.read(buffer);

			} finally {
				end();
			}

			return numBytes - buffer.remaining() /* should be zero */;
		}

		@Override
		public final int read(IntBuffer intBuffer) {

			final int numBytes = intBuffer.remaining();

			try {
				begin();

				_this.read(intBuffer);

			} finally {
				end();
			}

			return numBytes - intBuffer.remaining() /* should be zero */;
		}

		@Override
		public final int read(FloatBuffer floatBuffer) {

			final int numBytes = floatBuffer.remaining();

			try {
				begin();

				_this.read(floatBuffer);

			} finally {
				end();
			}

			return numBytes - floatBuffer.remaining() /* should be zero */;
		}

		@Override
		public final int read(LongBuffer longBuffer) {

			final int numBytes = longBuffer.remaining();

			try {
				begin();

				_this.read(longBuffer);

			} finally {
				end();
			}

			return numBytes - longBuffer.remaining() /* should be zero */;
		}

		@Override
		public final int read(DoubleBuffer doubleBuffer) {

			final int numBytes = doubleBuffer.remaining();

			try {
				begin();

				_this.read(doubleBuffer);

			} finally {
				end();
			}

			return numBytes - doubleBuffer.remaining() /* should be zero */;
		}

		// ///////////////////////////////////////////////////////////
		// /////////////// PRNG INTERNALS ////////////////////////////
		// ///////////////////////////////////////////////////////////

		private final int acquireCounter() {
			// wait until counter is released.
			int mti; // iteration counter
			AtomicInteger idx = this.idx;

			for (;;) {
				mti = idx.get();

				// possibly in generate function
				if (mti != -1) {
					if (idx.compareAndSet(mti, -1)) // lock
						return mti;
				}
			}
		}

		private final void releaseCounter(int counter) {
			idx.set(counter);
		}

		@Override
		public final int hashCode() {
			return _this.hashCode();
		}

		@Override
		public final boolean equals(Object obj) {
			if (obj instanceof PseudorandomnessSharedLock) {
				obj = ((PseudorandomnessSharedLock) obj).engine;
			}
			if (obj instanceof PseudorandomnessThreadLocal) {
				obj = ((PseudorandomnessThreadLocal) obj).engine;
			}

			return _this.equals(obj);
		}

		@Override
		public final String toString() {
			return _this.toString();
		}

		@Override
		public final Pseudorandomness copy() {
			if (!isOpen())
				throw new NonReadableChannelException();

			try {
				lock.lock();

				MT64 mt = (MT64) _this.copy();

				MT64.Shared sharedCopy = mt.new Shared();

				{ // copy intermediate state
					sharedCopy.nextByte = this.nextByte;
					sharedCopy.nextShort = this.nextShort;
					sharedCopy.nextInt = this.nextInt;
					sharedCopy.nextLong = this.nextLong;

					sharedCopy.newByte = this.newByte;
					sharedCopy.newShort = this.newShort;
					sharedCopy.newInt = this.newInt;

					sharedCopy.mask8 = this.mask8;

					sharedCopy.word8 = this.word8;
					sharedCopy.word16 = this.word16;
					sharedCopy.word32 = this.word32;
					sharedCopy.word64 = this.word64;
				}

				return sharedCopy;

			} finally {
				lock.unlock();
			}
		}

		// ///////////////////////////////////////////////
		// /////////////// PRNG nextXXX //////////////////
		// ///////////////////////////////////////////////

		private volatile int mask8 = 1;

		// //////////////// INTERMEDIATE STATE/// ////////////////////
		private volatile byte word8; // eight bits
		private volatile short word16;; // two bytes
		private volatile int word32; // two shorts
		private volatile long word64; // two int's

		private volatile boolean newByte = true; // we need new byte?
		private volatile boolean newShort = true; // we need new short?
		private volatile boolean newInt = true; // we need new int?

		private volatile boolean nextByte = true; // generated next byte?
		private volatile boolean nextShort = true; // generated next short?
		private volatile boolean nextInt = true; // generated next int?
		private volatile boolean nextLong = true;// generated next long?

		@Override
		public final boolean nextBoolean() {
			if (!isOpen())
				throw new NonReadableChannelException();

			if (mask8 == 1 || (nextInt || nextLong || nextByte || nextShort)) {
				word8 = nextByte();
				mask8 = 256;
				nextByte = nextShort = nextInt = nextLong = false;
			}

			return (word8 & (mask8 >>>= 1)) != 0;
		}

		@Override
		public byte nextByte() {
			if (!isOpen())
				throw new NonReadableChannelException();

			nextByte = true;

			if ((nextInt || nextLong || nextShort) || newByte) {
				word16 = nextShort();
				newByte = false;
				nextShort = nextInt = nextLong = false;
				return (byte) (word16 >>> 8); // high 8
			}

			newByte = true; // need new word16 at next cycle.
			return (byte) word16; // low 8;
		}

		@Override
		public short nextShort() {
			if (!isOpen())
				throw new NonReadableChannelException();

			nextShort = true;

			if ((nextInt || nextLong) || newShort) {
				word32 = nextInt();
				newShort = false;
				nextInt = nextLong = false;
				return (short) (word32 >>> 16); // high 16
			}

			newShort = true; // need new word32 at next cycle.

			return (short) (word32); // low 16;
		}

		@Override
		public final int nextInt() {
			if (!isOpen())
				throw new NonReadableChannelException();

			nextInt = true;
			if (nextLong || newInt) {
				word64 = nextLong();
				newInt = false;
				nextLong = false;
				return (int) (word64 >>> 32); // high 32
			}

			newInt = true;
			return (int) (word64); // low 32;
		}

		@Override
		public final float nextFloat() {
			if (!isOpen())
				throw new NonReadableChannelException();

			nextInt = true;

			if (nextLong || newInt) {
				word64 = nextLong();
				newInt = false;
				nextLong = false;

				return ((((int) (word64 >>> 32)) >>> 8) / ((float) (1 << 24))); // high
																				// 32
			}

			newInt = true;
			return ((((int) (word64)) >>> 8) / ((float) (1 << 24))); // low 32
		}

		@Override
		public long nextLong() {
			if (!isOpen())
				throw new NonReadableChannelException();

			nextLong = true;
			long x;

			// obtain value from internal buffer
			for (;;) {

				// get current index;
				int mtI = idx.get();
				int next = mtI + 1;
				// assert mtI == _this.mti : mtI + "	:	" + _this.mti;

				if (mtI < 0) // can't generate, buffer is not ready
					continue;

				if (mtI >= N) { /* generate NN words at one time */

					if (!idx.compareAndSet(mtI, -1)) // try acquire lock
						continue; // counter state is changed

					int i;
					final long[] mt = _this.mt; // locals are slightly faster

					for (i = 0; i < N - M; i++) {
						x = (mt[i] & UM) | (mt[i + 1] & LM);
						mt[i] = mt[i + M] ^ (x >>> 1) ^ mag01[(int) (x & 1L)];
					}
					for (; i < N - 1; i++) {
						x = (mt[i] & UM) | (mt[i + 1] & LM);
						mt[i] = mt[i + (M - N)] ^ (x >>> 1)
								^ mag01[(int) (x & 1L)];
					}
					x = (mt[N - 1] & UM) | (mt[0] & LM);
					mt[N - 1] = mt[M - 1] ^ (x >>> 1) ^ mag01[(int) (x & 1L)];

					x = mt[0];
					idx.set(mti = 1); // reset state from -1
					break;
				}

				x = mt[mtI];

				if (idx.compareAndSet(mtI, next)) {
					break;
				}
			}

			x ^= (x >>> 29) & 0x5555555555555555L;
			x ^= (x << 17) & 0x71D67FFFEDA60000L;
			x ^= (x << 37) & 0xFFF7EEE000000000L;
			x ^= (x >>> 43);

			return x;

		}

		@Override
		public double nextDouble() {
			if (!isOpen())
				throw new NonReadableChannelException();

			nextLong = true;
			long x;

			// obtain value from internal buffer
			for (;;) {

				// get current index;
				int mtI = idx.get();
				int next = mtI + 1;

				if (mtI < 0) // can't generate, buffer is not ready
					continue;

				if (mtI >= N) { /* generate NN words at one time */

					if (!idx.compareAndSet(mtI, -1)) // try acquire lock
						continue; // counter state is changed

					int i;
					final long[] mt = _this.mt; // locals are slightly faster

					for (i = 0; i < N - M; i++) {
						x = (mt[i] & UM) | (mt[i + 1] & LM);
						mt[i] = mt[i + M] ^ (x >>> 1) ^ mag01[(int) (x & 1L)];
					}
					for (; i < N - 1; i++) {
						x = (mt[i] & UM) | (mt[i + 1] & LM);
						mt[i] = mt[i + (M - N)] ^ (x >>> 1)
								^ mag01[(int) (x & 1L)];
					}
					x = (mt[N - 1] & UM) | (mt[0] & LM);
					mt[N - 1] = mt[M - 1] ^ (x >>> 1) ^ mag01[(int) (x & 1L)];

					x = mt[0];
					idx.set(mti = 1); // reset state from -1
					break;
				}

				x = mt[mtI];

				if (idx.compareAndSet(mtI, next)) {
					break;
				}
			}

			x ^= (x >>> 29) & 0x5555555555555555L;
			x ^= (x << 17) & 0x71D67FFFEDA60000L;
			x ^= (x << 37) & 0xFFF7EEE000000000L;
			x ^= (x >>> 43);

			return ((x) >>> 11) / (double) (1L << 53);
		}
	}
}