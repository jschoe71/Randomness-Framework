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
 * This is a Java version of the C-program for MT19937: Integer version. The
 * MT19937 algorithm was created by Makoto Matsumoto and Takuji Nishimura, who
 * ask: "When you use this, send an email to: matumoto@math.keio.ac.jp with an
 * appropriate reference to your work". Indicate that this is a translation of
 * their algorithm into Java.
 * <p>
 * <b>Version 13</b>, based on version MT199937(99/10/29) of the Mersenne
 * Twister algorithm found at <a
 * href="http://www.math.keio.ac.jp/matumoto/emt.html"> The Mersenne Twister
 * Home Page</a>, with the initialization improved using the new 2002/1/26
 * initialization algorithm By Sean Luke, October 2004.
 * <p>
 * The MersenneTwister code is based on standard MT19937 C/C++ code by Takuji
 * Nishimura, with suggestions from Topher Cooper and Marc Rieffel, July 1997.
 * The code was originally translated into Java by Michael Lecuyer, January
 * 1999, and the original code is Copyright (c) 1999 by Michael Lecuyer.
 * 
 * 
 * <h3>License</h3>
 * 
 * Copyright (c) 2003 by Sean Luke. <br>
 * Portions copyright (c) 1993 by Michael Lecuyer. <br>
 * All rights reserved. <br>
 * 
 * <p>
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * <ul>
 * <li>Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 * <li>Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 * <li>Neither the name of the copyright owners, their employers, nor the names
 * of its contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 * </ul>
 * 
 * @version 13
 * @author Anton Kabysh (randomness adaptation)
 * @author Sean Luke
 * @author Michael Lecuyer
 */

// Note: this class is hard-inlined in all of its methods. This makes some of
// the methods well-nigh unreadable in their complexity.
final class MT extends PseudorandomnessEngine implements Engine.MT {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	// Period parameters
	private static final int N = 624;
	private static final int M = 397;
	private static final int MATRIX_A = 0x9908b0df; // private static final *
	// constant vector a
	private static final int UPPER_MASK = 0x80000000; // most significant w-r
	// bits
	private static final int LOWER_MASK = 0x7fffffff; // least significant r
	// bits

	// Tempering parameters
	private static final int TEMPERING_MASK_B = 0x9d2c5680;
	private static final int TEMPERING_MASK_C = 0xefc60000;

	private int mt[]; // the array for the state vector
	private int mti; // mti==N+1 means mt[N] is not initialized
	private int mag01[];

	// a good initial seed (of int size, though stored in a long)
	// private static final long GOOD_SEED = 4357;

	// private double __nextNextGaussian;
	// private boolean __haveNextNextGaussian;

	MT() {
		this.reset();
	}

	@Override
	protected final void instantiate(ByteBuffer seed) {
		// ////////////////// INSTANTIATE FUNCTION ////////////////////////
		// convert seed bytes to int array
		int[] array = new int[seedlen() / INT_SIZE_BYTES];
		int zeroidx = 1;
		for (int i = 0; i < array.length; i++) {
			array[i] = seed.getInt();
			if (array[i] != 0)
				zeroidx = (i + 1);
		}

		// initGenRandom(int)
		if (zeroidx == 1) {
			initGenRandom(array[0]);
			return;
		}

		// initGenRandom(long)
		if (zeroidx == 2) {
			initGenRandom((((long) array[0]) << 32) + (long) array[1]);
			return;
		}

		int i, j, k;
		initGenRandom(19650218);

		i = 1;
		j = 0;
		k = (N > array.length ? N : array.length);

		for (; k != 0; k--) {
			mt[i] = (mt[i] ^ ((mt[i - 1] ^ (mt[i - 1] >>> 30)) * 1664525))
					+ array[j] + j; /* non linear */
			mt[i] &= 0xffffffff; /* for WORDSIZE > 32 machines */
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
			mt[i] = (mt[i] ^ ((mt[i - 1] ^ (mt[i - 1] >>> 30)) * 1566083941))
					- i; /* non linear */
			mt[i] &= 0xffffffff; /* for WORDSIZE > 32 machines */
			i++;
			if (i >= N) {
				mt[0] = mt[N - 1];
				i = 1;
			}
		}
		mt[0] = 0x80000000; /* MSB is 1; assuring non-zero initial array */
		// ////////////////// INSTANTIATE FUNCTION ////////////////////////
		// /////////////////// GENERATE FUNCTION ///////////////////////////
		int y;

		if (mti >= N) // generate N words at one time
		{
			int kk;
			final int[] mt = this.mt; // locals are slightly faster
			final int[] mag01 = this.mag01; // locals are slightly
											// faster

			for (kk = 0; kk < N - M; kk++) {
				y = (mt[kk] & UPPER_MASK) | (mt[kk + 1] & LOWER_MASK);
				mt[kk] = mt[kk + M] ^ (y >>> 1) ^ mag01[y & 0x1];
			}
			for (; kk < N - 1; kk++) {
				y = (mt[kk] & UPPER_MASK) | (mt[kk + 1] & LOWER_MASK);
				mt[kk] = mt[kk + (M - N)] ^ (y >>> 1) ^ mag01[y & 0x1];
			}
			y = (mt[N - 1] & UPPER_MASK) | (mt[0] & LOWER_MASK);
			mt[N - 1] = mt[M - 1] ^ (y >>> 1) ^ mag01[y & 0x1];

			mti = 0;
		}
		// ////////////////////// GENERATE FUNCTION /////////////////////////
	}

	private final void initGenRandom(final long seed) {
		// Due to a bug in java.util.Random clear up to 1.2, we're
		// doing our own Gaussian variable.
		// __haveNextNextGaussian = false;

		mt = new int[N];

		mag01 = new int[2];
		mag01[0] = 0x0;
		mag01[1] = MATRIX_A;

		mt[0] = (int) (seed & 0xffffffff);
		for (mti = 1; mti < N; mti++) {
			mt[mti] = (1812433253 * (mt[mti - 1] ^ (mt[mti - 1] >>> 30)) + mti);
			/* See Knuth TAOCP Vol2. 3rd Ed. P.106 for multiplier. */
			/* In the previous versions, MSBs of the seed affect */
			/* only MSBs of the array mt[]. */
			/* 2002/01/09 modified by Makoto Matsumoto */
			mt[mti] &= 0xffffffff;
			/* for >32 bit machines */
		}
	}

	@Override
	public final int read(ByteBuffer buffer) {
		final int numBytes = buffer.remaining();

		int bytes = 0;

		for (; (numBytes - bytes) >= INT_SIZE_BYTES;) {

			if (shared && !isOpen()) // check interruption status
				return bytes; // interrupt

			// ///////////////// GENERATE FUNCTION /////////////////////
			int y;

			if (mti >= N) // generate N words at one time
			{
				int kk;
				final int[] mt = this.mt; // locals are slightly faster
				final int[] mag01 = this.mag01; // locals are slightly
				// faster

				for (kk = 0; kk < N - M; kk++) {
					y = (mt[kk] & UPPER_MASK) | (mt[kk + 1] & LOWER_MASK);
					mt[kk] = mt[kk + M] ^ (y >>> 1) ^ mag01[y & 0x1];
				}
				for (; kk < N - 1; kk++) {
					y = (mt[kk] & UPPER_MASK) | (mt[kk + 1] & LOWER_MASK);
					mt[kk] = mt[kk + (M - N)] ^ (y >>> 1) ^ mag01[y & 0x1];
				}
				y = (mt[N - 1] & UPPER_MASK) | (mt[0] & LOWER_MASK);
				mt[N - 1] = mt[M - 1] ^ (y >>> 1) ^ mag01[y & 0x1];

				mti = 0;

				// //////////////// BLOCK MODE ///////////////////////////////
				if ((numBytes - bytes) >= (INT_SIZE_BYTES * N)) {
					int[] words = new int[N];
					for (y = 0; mti < N;) {
						y = mt[mti];
						y ^= y >>> 11; // TEMPERING_SHIFT_U(y)
						y ^= (y << 7) & TEMPERING_MASK_B; // TEMPERING_SHIFT_S(y)
						y ^= (y << 15) & TEMPERING_MASK_C; // TEMPERING_SHIFT_T(y)
						y ^= (y >>> 18); // TEMPERING_SHIFT_L(y)
						words[mti++] = y;
						// buffer.putInt(y);

						y = mt[mti];
						y ^= y >>> 11; // TEMPERING_SHIFT_U(y)
						y ^= (y << 7) & TEMPERING_MASK_B; // TEMPERING_SHIFT_S(y)
						y ^= (y << 15) & TEMPERING_MASK_C; // TEMPERING_SHIFT_T(y)
						y ^= (y >>> 18); // TEMPERING_SHIFT_L(y)
						// buffer.putInt(y);
						words[mti++] = y;

						y = mt[mti];
						y ^= y >>> 11; // TEMPERING_SHIFT_U(y)
						y ^= (y << 7) & TEMPERING_MASK_B; // TEMPERING_SHIFT_S(y)
						y ^= (y << 15) & TEMPERING_MASK_C; // TEMPERING_SHIFT_T(y)
						y ^= (y >>> 18); // TEMPERING_SHIFT_L(y)
						// buffer.putInt(y);
						words[mti++] = y;

						y = mt[mti];
						y ^= y >>> 11; // TEMPERING_SHIFT_U(y)
						y ^= (y << 7) & TEMPERING_MASK_B; // TEMPERING_SHIFT_S(y)
						y ^= (y << 15) & TEMPERING_MASK_C; // TEMPERING_SHIFT_T(y)
						y ^= (y >>> 18); // TEMPERING_SHIFT_L(y)
						// buffer.putInt(y);
						words[mti++] = y;

					}
					buffer.slice().asIntBuffer().put(words);
					buffer.position(buffer.position() + (INT_SIZE_BYTES * N));
					bytes += INT_SIZE_BYTES * N; // inc bytes
					continue;
				}
				// //////////////// BLOCK MODE ///////////////////////////////
			}

			y = mt[mti++];
			y ^= y >>> 11; // TEMPERING_SHIFT_U(y)
			y ^= (y << 7) & TEMPERING_MASK_B; // TEMPERING_SHIFT_S(y)
			y ^= (y << 15) & TEMPERING_MASK_C; // TEMPERING_SHIFT_T(y)
			y ^= (y >>> 18); // TEMPERING_SHIFT_L(y)

			// ///////////////// GENERATE FUNCTION /////////////////////
			buffer.putInt(y);
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

		final int[] mt = this.mt; // locals are slightly faster

		final int numInts = intBuffer.remaining();

		int ints = 0;

		for (; ints < numInts;) {

			if (shared && !isOpen())
				return ints; // interrupt

			// ///////////////// GENERATE FUNCTION /////////////////////
			int y;

			if (mti >= N) // generate N words at one time
			{
				int kk;
				final int[] mag01 = this.mag01; // locals are slightly
				// faster

				for (kk = 0; kk < N - M; kk++) {
					y = (mt[kk] & UPPER_MASK) | (mt[kk + 1] & LOWER_MASK);
					mt[kk] = mt[kk + M] ^ (y >>> 1) ^ mag01[y & 0x1];
				}
				for (; kk < N - 1; kk++) {
					y = (mt[kk] & UPPER_MASK) | (mt[kk + 1] & LOWER_MASK);
					mt[kk] = mt[kk + (M - N)] ^ (y >>> 1) ^ mag01[y & 0x1];
				}
				y = (mt[N - 1] & UPPER_MASK) | (mt[0] & LOWER_MASK);
				mt[N - 1] = mt[M - 1] ^ (y >>> 1) ^ mag01[y & 0x1];

				mti = 0;

				// //////////////// BLOCK MODE ///////////////////////////////
				if (intBuffer.remaining() >= N) {
					final int[] words = new int[N];
					for (y = 0; mti < N;) {
						y = mt[mti];
						y ^= y >>> 11; // TEMPERING_SHIFT_U(y)
						y ^= (y << 7) & TEMPERING_MASK_B; // TEMPERING_SHIFT_S(y)
						y ^= (y << 15) & TEMPERING_MASK_C; // TEMPERING_SHIFT_T(y)
						y ^= (y >>> 18); // TEMPERING_SHIFT_L(y)
						words[mti++] = y;

						y = mt[mti];
						y ^= y >>> 11; // TEMPERING_SHIFT_U(y)
						y ^= (y << 7) & TEMPERING_MASK_B; // TEMPERING_SHIFT_S(y)
						y ^= (y << 15) & TEMPERING_MASK_C; // TEMPERING_SHIFT_T(y)
						y ^= (y >>> 18); // TEMPERING_SHIFT_L(y)
						words[mti++] = y;

						y = mt[mti];
						y ^= y >>> 11; // TEMPERING_SHIFT_U(y)
						y ^= (y << 7) & TEMPERING_MASK_B; // TEMPERING_SHIFT_S(y)
						y ^= (y << 15) & TEMPERING_MASK_C; // TEMPERING_SHIFT_T(y)
						y ^= (y >>> 18); // TEMPERING_SHIFT_L(y)
						words[mti++] = y;

						y = mt[mti];
						y ^= y >>> 11; // TEMPERING_SHIFT_U(y)
						y ^= (y << 7) & TEMPERING_MASK_B; // TEMPERING_SHIFT_S(y)
						y ^= (y << 15) & TEMPERING_MASK_C; // TEMPERING_SHIFT_T(y)
						y ^= (y >>> 18); // TEMPERING_SHIFT_L(y)
						words[mti++] = y;

						y = mt[mti];
						y ^= y >>> 11; // TEMPERING_SHIFT_U(y)
						y ^= (y << 7) & TEMPERING_MASK_B; // TEMPERING_SHIFT_S(y)
						y ^= (y << 15) & TEMPERING_MASK_C; // TEMPERING_SHIFT_T(y)
						y ^= (y >>> 18); // TEMPERING_SHIFT_L(y)
						words[mti++] = y;

						y = mt[mti];
						y ^= y >>> 11; // TEMPERING_SHIFT_U(y)
						y ^= (y << 7) & TEMPERING_MASK_B; // TEMPERING_SHIFT_S(y)
						y ^= (y << 15) & TEMPERING_MASK_C; // TEMPERING_SHIFT_T(y)
						y ^= (y >>> 18); // TEMPERING_SHIFT_L(y)
						words[mti++] = y;

						y = mt[mti];
						y ^= y >>> 11; // TEMPERING_SHIFT_U(y)
						y ^= (y << 7) & TEMPERING_MASK_B; // TEMPERING_SHIFT_S(y)
						y ^= (y << 15) & TEMPERING_MASK_C; // TEMPERING_SHIFT_T(y)
						y ^= (y >>> 18); // TEMPERING_SHIFT_L(y)
						words[mti++] = y;

						y = mt[mti];
						y ^= y >>> 11; // TEMPERING_SHIFT_U(y)
						y ^= (y << 7) & TEMPERING_MASK_B; // TEMPERING_SHIFT_S(y)
						y ^= (y << 15) & TEMPERING_MASK_C; // TEMPERING_SHIFT_T(y)
						y ^= (y >>> 18); // TEMPERING_SHIFT_L(y)
						words[mti++] = y;
					}
					intBuffer.put(words);
					ints += N;
					continue;
				}
				// //////////////// BLOCK MODE ///////////////////////////////
			}

			y = mt[mti++];
			y ^= y >>> 11; // TEMPERING_SHIFT_U(y)
			y ^= (y << 7) & TEMPERING_MASK_B; // TEMPERING_SHIFT_S(y)
			y ^= (y << 15) & TEMPERING_MASK_C; // TEMPERING_SHIFT_T(y)
			y ^= (y >>> 18); // TEMPERING_SHIFT_L(y)

			// ///////////////// GENERATE FUNCTION /////////////////////

			intBuffer.put(y);
			ints++;
		}

		return numInts - intBuffer.remaining();
	}

	@Override
	public int read(FloatBuffer floatBuffer) {

		final int numFloats = floatBuffer.remaining();

		int floats = 0;

		for (; floats < numFloats;) {

			if (shared && !isOpen())
				return floats; // interrupt

			// ///////////////// GENERATE FUNCTION /////////////////////
			int y;

			if (mti >= N) // generate N words at one time
			{
				int kk;
				final int[] mt = this.mt; // locals are slightly faster
				final int[] mag01 = this.mag01; // locals are slightly
												// faster

				for (kk = 0; kk < N - M; kk++) {
					y = (mt[kk] & UPPER_MASK) | (mt[kk + 1] & LOWER_MASK);
					mt[kk] = mt[kk + M] ^ (y >>> 1) ^ mag01[y & 0x1];
				}
				for (; kk < N - 1; kk++) {
					y = (mt[kk] & UPPER_MASK) | (mt[kk + 1] & LOWER_MASK);
					mt[kk] = mt[kk + (M - N)] ^ (y >>> 1) ^ mag01[y & 0x1];
				}
				y = (mt[N - 1] & UPPER_MASK) | (mt[0] & LOWER_MASK);
				mt[N - 1] = mt[M - 1] ^ (y >>> 1) ^ mag01[y & 0x1];

				mti = 0;

				// //////////////// BLOCK MODE ///////////////////////////////
				if (floatBuffer.remaining() >= N) {

					for (y = 0; mti < N;) {
						y = mt[mti++];
						y ^= y >>> 11; // TEMPERING_SHIFT_U(y)
						y ^= (y << 7) & TEMPERING_MASK_B; // TEMPERING_SHIFT_S(y)
						y ^= (y << 15) & TEMPERING_MASK_C; // TEMPERING_SHIFT_T(y)
						y ^= (y >>> 18); // TEMPERING_SHIFT_L(y)
						floatBuffer.put((y >>> 8) / ((float) (1 << 24)));

						y = mt[mti++];
						y ^= y >>> 11; // TEMPERING_SHIFT_U(y)
						y ^= (y << 7) & TEMPERING_MASK_B; // TEMPERING_SHIFT_S(y)
						y ^= (y << 15) & TEMPERING_MASK_C; // TEMPERING_SHIFT_T(y)
						y ^= (y >>> 18); // TEMPERING_SHIFT_L(y)
						floatBuffer.put((y >>> 8) / ((float) (1 << 24)));

						y = mt[mti++];
						y ^= y >>> 11; // TEMPERING_SHIFT_U(y)
						y ^= (y << 7) & TEMPERING_MASK_B; // TEMPERING_SHIFT_S(y)
						y ^= (y << 15) & TEMPERING_MASK_C; // TEMPERING_SHIFT_T(y)
						y ^= (y >>> 18); // TEMPERING_SHIFT_L(y)
						floatBuffer.put((y >>> 8) / ((float) (1 << 24)));

						y = mt[mti++];
						y ^= y >>> 11; // TEMPERING_SHIFT_U(y)
						y ^= (y << 7) & TEMPERING_MASK_B; // TEMPERING_SHIFT_S(y)
						y ^= (y << 15) & TEMPERING_MASK_C; // TEMPERING_SHIFT_T(y)
						y ^= (y >>> 18); // TEMPERING_SHIFT_L(y)
						floatBuffer.put((y >>> 8) / ((float) (1 << 24)));
					}

					floats += N;
					continue;
				}
				// //////////////// BLOCK MODE ///////////////////////////////
			}

			y = mt[mti++];
			y ^= y >>> 11; // TEMPERING_SHIFT_U(y)
			y ^= (y << 7) & TEMPERING_MASK_B; // TEMPERING_SHIFT_S(y)
			y ^= (y << 15) & TEMPERING_MASK_C; // TEMPERING_SHIFT_T(y)
			y ^= (y >>> 18); // TEMPERING_SHIFT_L(y)

			// ///////////////// GENERATE FUNCTION /////////////////////
			floatBuffer.put((y >>> 8) / ((float) (1 << 24)));
			floats++;
		}

		return numFloats - floatBuffer.remaining();

	}

	@Override
	public final int read(LongBuffer longBuffer) {

		final int numLongs = longBuffer.remaining();
		final boolean even = (mti % 2) == 0; // block mode depends from oddity
												// of
												// index

		for (int longs = 0; longs < numLongs;) {

			if (shared && !isOpen()) // check interruption status
				return longs; // interrupt
			// ///////////////// GENERATE FUNCTION /////////////////////
			int l;
			int r;

			if (mti >= N) // generate N words at one time
			{
				int y;
				int kk;
				final int[] mt = this.mt; // locals are slightly faster
				final int[] mag01 = this.mag01; // locals are slightly
												// faster

				for (kk = 0; kk < N - M; kk++) {
					y = (mt[kk] & UPPER_MASK) | (mt[kk + 1] & LOWER_MASK);
					mt[kk] = mt[kk + M] ^ (y >>> 1) ^ mag01[y & 0x1];
				}
				for (; kk < N - 1; kk++) {
					y = (mt[kk] & UPPER_MASK) | (mt[kk + 1] & LOWER_MASK);
					mt[kk] = mt[kk + (M - N)] ^ (y >>> 1) ^ mag01[y & 0x1];
				}
				y = (mt[N - 1] & UPPER_MASK) | (mt[0] & LOWER_MASK);
				mt[N - 1] = mt[M - 1] ^ (y >>> 1) ^ mag01[y & 0x1];

				mti = 0;

				// //////////////// BLOCK MODE ///////////////////////////////
				if (even && longBuffer.remaining() >= 312) {

					for (y = 0; mti < N;) {

						{
							l = mt[mti++];
							l ^= l >>> 11; // TEMPERING_SHIFT_U(y)
							l ^= (l << 7) & TEMPERING_MASK_B; // TEMPERING_SHIFT_S(y)
							l ^= (l << 15) & TEMPERING_MASK_C; // TEMPERING_SHIFT_T(y)
							l ^= (l >>> 18); // TEMPERING_SHIFT_L(y)

							r = mt[mti++];
							r ^= r >>> 11; // TEMPERING_SHIFT_U(y)
							r ^= (r << 7) & TEMPERING_MASK_B; // TEMPERING_SHIFT_S(y)
							r ^= (r << 15) & TEMPERING_MASK_C; // TEMPERING_SHIFT_T(y)
							r ^= (r >>> 18); // TEMPERING_SHIFT_L(y)

							longBuffer.put((((long) l) << 32) + r);
						}
						{
							l = mt[mti++];
							l ^= l >>> 11; // TEMPERING_SHIFT_U(y)
							l ^= (l << 7) & TEMPERING_MASK_B; // TEMPERING_SHIFT_S(y)
							l ^= (l << 15) & TEMPERING_MASK_C; // TEMPERING_SHIFT_T(y)
							l ^= (l >>> 18); // TEMPERING_SHIFT_L(y)

							r = mt[mti++];
							r ^= r >>> 11; // TEMPERING_SHIFT_U(y)
							r ^= (r << 7) & TEMPERING_MASK_B; // TEMPERING_SHIFT_S(y)
							r ^= (r << 15) & TEMPERING_MASK_C; // TEMPERING_SHIFT_T(y)
							r ^= (r >>> 18); // TEMPERING_SHIFT_L(y)

							longBuffer.put((((long) l) << 32) + r);
						}

					}

					longs += 312;
					continue;
				}
			}

			l = mt[mti++];
			l ^= l >>> 11; // TEMPERING_SHIFT_U(y)
			l ^= (l << 7) & TEMPERING_MASK_B; // TEMPERING_SHIFT_S(y)
			l ^= (l << 15) & TEMPERING_MASK_C; // TEMPERING_SHIFT_T(y)
			l ^= (l >>> 18); // TEMPERING_SHIFT_L(y)

			if (mti >= N) // generate N words at one time
			{
				int y;
				int kk;
				final int[] mt = this.mt; // locals are slightly faster
				final int[] mag01 = this.mag01; // locals are slightly
												// faster

				for (kk = 0; kk < N - M; kk++) {
					y = (mt[kk] & UPPER_MASK) | (mt[kk + 1] & LOWER_MASK);
					mt[kk] = mt[kk + M] ^ (y >>> 1) ^ mag01[y & 0x1];
				}
				for (; kk < N - 1; kk++) {
					y = (mt[kk] & UPPER_MASK) | (mt[kk + 1] & LOWER_MASK);
					mt[kk] = mt[kk + (M - N)] ^ (y >>> 1) ^ mag01[y & 0x1];
				}
				y = (mt[N - 1] & UPPER_MASK) | (mt[0] & LOWER_MASK);
				mt[N - 1] = mt[M - 1] ^ (y >>> 1) ^ mag01[y & 0x1];

				mti = 0;

				// ////////////// BLOCK MODE (ODD CASE) /////////////////
				if (!even && longBuffer.remaining() >= 312) {
					{
						r = mt[mti++];
						r ^= r >>> 11; // TEMPERING_SHIFT_U(y)
						r ^= (r << 7) & TEMPERING_MASK_B; // TEMPERING_SHIFT_S(y)
						r ^= (r << 15) & TEMPERING_MASK_C; // TEMPERING_SHIFT_T(y)
						r ^= (r >>> 18); // TEMPERING_SHIFT_L(y)
						longBuffer.put((((long) l) << 32) + r);
						longs++;
					}

					for (y = 0; mti < (N - 1);) {

						l = mt[mti++];
						l ^= l >>> 11; // TEMPERING_SHIFT_U(y)
						l ^= (l << 7) & TEMPERING_MASK_B; // TEMPERING_SHIFT_S(y)
						l ^= (l << 15) & TEMPERING_MASK_C; // TEMPERING_SHIFT_T(y)
						l ^= (l >>> 18); // TEMPERING_SHIFT_L(y)

						r = mt[mti++];
						r ^= r >>> 11; // TEMPERING_SHIFT_U(y)
						r ^= (r << 7) & TEMPERING_MASK_B; // TEMPERING_SHIFT_S(y)
						r ^= (r << 15) & TEMPERING_MASK_C; // TEMPERING_SHIFT_T(y)
						r ^= (r >>> 18); // TEMPERING_SHIFT_L(y)

						longBuffer.put((((long) l) << 32) + r);

					}
					longs += 311;
					continue;
				}
				// //////////////// BLOCK MODE /////////////////
			}

			r = mt[mti++];
			r ^= r >>> 11; // TEMPERING_SHIFT_U(y)
			r ^= (r << 7) & TEMPERING_MASK_B; // TEMPERING_SHIFT_S(y)
			r ^= (r << 15) & TEMPERING_MASK_C; // TEMPERING_SHIFT_T(y)
			r ^= (r >>> 18); // TEMPERING_SHIFT_L(y)

			longBuffer.put((((long) l) << 32) + r);
			longs++;
			// ///////////////// GENERATE FUNCTION /////////////////////

		}

		return numLongs - longBuffer.remaining();
	}

	@Override
	public final int read(DoubleBuffer doubleBuffer) {
		final int numDoubles = doubleBuffer.remaining();

		int doubles = 0;

		final boolean even = (mti % 2) == 0;

		for (; doubles < numDoubles;) {

			if (shared && !isOpen())
				return doubles; // interrupt

			// ///////////////// GENERATE FUNCTION /////////////////////
			int l;
			int r;

			if (mti >= N) // generate N words at one time
			{
				int y;
				int kk;
				final int[] mt = this.mt; // locals are slightly faster
				final int[] mag01 = this.mag01; // locals are slightly
												// faster

				for (kk = 0; kk < N - M; kk++) {
					y = (mt[kk] & UPPER_MASK) | (mt[kk + 1] & LOWER_MASK);
					mt[kk] = mt[kk + M] ^ (y >>> 1) ^ mag01[y & 0x1];
				}
				for (; kk < N - 1; kk++) {
					y = (mt[kk] & UPPER_MASK) | (mt[kk + 1] & LOWER_MASK);
					mt[kk] = mt[kk + (M - N)] ^ (y >>> 1) ^ mag01[y & 0x1];
				}
				y = (mt[N - 1] & UPPER_MASK) | (mt[0] & LOWER_MASK);
				mt[N - 1] = mt[M - 1] ^ (y >>> 1) ^ mag01[y & 0x1];

				mti = 0;

				// //////////////// BLOCK MODE ///////////////////////////////
				if (doubleBuffer.remaining() >= 312) {

					for (y = 0; mti < N;) {

						{
							l = mt[mti++];
							l ^= l >>> 11; // TEMPERING_SHIFT_U(y)
							l ^= (l << 7) & TEMPERING_MASK_B; // TEMPERING_SHIFT_S(y)
							l ^= (l << 15) & TEMPERING_MASK_C; // TEMPERING_SHIFT_T(y)
							l ^= (l >>> 18); // TEMPERING_SHIFT_L(y)

							r = mt[mti++];
							r ^= r >>> 11; // TEMPERING_SHIFT_U(y)
							r ^= (r << 7) & TEMPERING_MASK_B; // TEMPERING_SHIFT_S(y)
							r ^= (r << 15) & TEMPERING_MASK_C; // TEMPERING_SHIFT_T(y)
							r ^= (r >>> 18); // TEMPERING_SHIFT_L(y)

							doubleBuffer
									.put(((((long) (l >>> 6)) << 27) + (r >>> 5))
											/ (double) (1L << 53));
						}
						{
							l = mt[mti++];
							l ^= l >>> 11; // TEMPERING_SHIFT_U(y)
							l ^= (l << 7) & TEMPERING_MASK_B; // TEMPERING_SHIFT_S(y)
							l ^= (l << 15) & TEMPERING_MASK_C; // TEMPERING_SHIFT_T(y)
							l ^= (l >>> 18); // TEMPERING_SHIFT_L(y)

							r = mt[mti++];
							r ^= r >>> 11; // TEMPERING_SHIFT_U(y)
							r ^= (r << 7) & TEMPERING_MASK_B; // TEMPERING_SHIFT_S(y)
							r ^= (r << 15) & TEMPERING_MASK_C; // TEMPERING_SHIFT_T(y)
							r ^= (r >>> 18); // TEMPERING_SHIFT_L(y)

							doubleBuffer
									.put(((((long) (l >>> 6)) << 27) + (r >>> 5))
											/ (double) (1L << 53));
						}

					}

					doubles += 312;
					continue;
				}
			}

			l = mt[mti++];
			l ^= l >>> 11; // TEMPERING_SHIFT_U(y)
			l ^= (l << 7) & TEMPERING_MASK_B; // TEMPERING_SHIFT_S(y)
			l ^= (l << 15) & TEMPERING_MASK_C; // TEMPERING_SHIFT_T(y)
			l ^= (l >>> 18); // TEMPERING_SHIFT_L(y)

			if (mti >= N) // generate N words at one time
			{
				int y;
				int kk;
				final int[] mt = this.mt; // locals are slightly faster
				final int[] mag01 = this.mag01; // locals are slightly
												// faster

				for (kk = 0; kk < N - M; kk++) {
					y = (mt[kk] & UPPER_MASK) | (mt[kk + 1] & LOWER_MASK);
					mt[kk] = mt[kk + M] ^ (y >>> 1) ^ mag01[y & 0x1];
				}
				for (; kk < N - 1; kk++) {
					y = (mt[kk] & UPPER_MASK) | (mt[kk + 1] & LOWER_MASK);
					mt[kk] = mt[kk + (M - N)] ^ (y >>> 1) ^ mag01[y & 0x1];
				}
				y = (mt[N - 1] & UPPER_MASK) | (mt[0] & LOWER_MASK);
				mt[N - 1] = mt[M - 1] ^ (y >>> 1) ^ mag01[y & 0x1];

				mti = 0;

				// ////////////// BLOCK MODE (ODD CASE) /////////////////
				if (!even && doubleBuffer.remaining() >= 312) {
					{ // / put second half
						r = mt[mti++];
						r ^= r >>> 11; // TEMPERING_SHIFT_U(y)
						r ^= (r << 7) & TEMPERING_MASK_B; // TEMPERING_SHIFT_S(y)
						r ^= (r << 15) & TEMPERING_MASK_C; // TEMPERING_SHIFT_T(y)
						r ^= (r >>> 18); // TEMPERING_SHIFT_L(y)
						doubleBuffer
								.put(((((long) (l >>> 6)) << 27) + (r >>> 5))
										/ (double) (1L << 53));
						doubles++;
					}

					for (y = 0; mti < (N - 1);) {

						l = mt[mti++];
						l ^= l >>> 11; // TEMPERING_SHIFT_U(y)
						l ^= (l << 7) & TEMPERING_MASK_B; // TEMPERING_SHIFT_S(y)
						l ^= (l << 15) & TEMPERING_MASK_C; // TEMPERING_SHIFT_T(y)
						l ^= (l >>> 18); // TEMPERING_SHIFT_L(y)

						r = mt[mti++];
						r ^= r >>> 11; // TEMPERING_SHIFT_U(y)
						r ^= (r << 7) & TEMPERING_MASK_B; // TEMPERING_SHIFT_S(y)
						r ^= (r << 15) & TEMPERING_MASK_C; // TEMPERING_SHIFT_T(y)
						r ^= (r >>> 18); // TEMPERING_SHIFT_L(y)

						doubleBuffer
								.put(((((long) (l >>> 6)) << 27) + (r >>> 5))
										/ (double) (1L << 53));
					}
					doubles += 311;
					continue;
				}
				// //////////////// BLOCK MODE /////////////////
			}

			r = mt[mti++];
			r ^= r >>> 11; // TEMPERING_SHIFT_U(y)
			r ^= (r << 7) & TEMPERING_MASK_B; // TEMPERING_SHIFT_S(y)
			r ^= (r << 15) & TEMPERING_MASK_C; // TEMPERING_SHIFT_T(y)
			r ^= (r >>> 18); // TEMPERING_SHIFT_L(y)

			doubleBuffer.put(((((long) (l >>> 6)) << 27) + (r >>> 5))
					/ (double) (1L << 53));
			doubles++;
			// ///////////////// GENERATE FUNCTION /////////////////////

		}

		return numDoubles - doubleBuffer.remaining() /* should be zero */;
	}

	private int generate32() {
		int y;

		if (mti >= N) // generate N words at one time
		{
			int kk;
			final int[] mt = this.mt; // locals are slightly faster
			final int[] mag01 = this.mag01; // locals are slightly faster

			for (kk = 0; kk < N - M; kk++) {
				y = (mt[kk] & UPPER_MASK) | (mt[kk + 1] & LOWER_MASK);
				mt[kk] = mt[kk + M] ^ (y >>> 1) ^ mag01[y & 0x1];
			}
			for (; kk < N - 1; kk++) {
				y = (mt[kk] & UPPER_MASK) | (mt[kk + 1] & LOWER_MASK);
				mt[kk] = mt[kk + (M - N)] ^ (y >>> 1) ^ mag01[y & 0x1];
			}
			y = (mt[N - 1] & UPPER_MASK) | (mt[0] & LOWER_MASK);
			mt[N - 1] = mt[M - 1] ^ (y >>> 1) ^ mag01[y & 0x1];

			mti = 0;
		}

		y = mt[mti++];
		y ^= y >>> 11; // TEMPERING_SHIFT_U(y)
		y ^= (y << 7) & TEMPERING_MASK_B; // TEMPERING_SHIFT_S(y)
		y ^= (y << 15) & TEMPERING_MASK_C; // TEMPERING_SHIFT_T(y)
		y ^= (y >>> 18); // TEMPERING_SHIFT_L(y)

		return y;
	}

	public final int nextInt() {
		int y;

		if (mti >= N) // generate N words at one time
		{
			int kk;
			final int[] mt = this.mt; // locals are slightly faster
			final int[] mag01 = this.mag01; // locals are slightly faster

			for (kk = 0; kk < N - M; kk++) {
				y = (mt[kk] & UPPER_MASK) | (mt[kk + 1] & LOWER_MASK);
				mt[kk] = mt[kk + M] ^ (y >>> 1) ^ mag01[y & 0x1];
			}
			for (; kk < N - 1; kk++) {
				y = (mt[kk] & UPPER_MASK) | (mt[kk + 1] & LOWER_MASK);
				mt[kk] = mt[kk + (M - N)] ^ (y >>> 1) ^ mag01[y & 0x1];
			}
			y = (mt[N - 1] & UPPER_MASK) | (mt[0] & LOWER_MASK);
			mt[N - 1] = mt[M - 1] ^ (y >>> 1) ^ mag01[y & 0x1];

			mti = 0;
		}

		y = mt[mti++];

		y ^= y >>> 11; // TEMPERING_SHIFT_U(y)
		y ^= (y << 7) & TEMPERING_MASK_B; // TEMPERING_SHIFT_S(y)
		y ^= (y << 15) & TEMPERING_MASK_C; // TEMPERING_SHIFT_T(y)
		y ^= (y >>> 18); // TEMPERING_SHIFT_L(y)

		return y;
	}

	public final byte nextByte() {

		int y;
		if (mti >= N) // generate N words at one time
		{
			int kk;
			final int[] mt = this.mt; // locals are slightly faster
			final int[] mag01 = this.mag01; // locals are slightly faster

			for (kk = 0; kk < N - M; kk++) {
				y = (mt[kk] & UPPER_MASK) | (mt[kk + 1] & LOWER_MASK);
				mt[kk] = mt[kk + M] ^ (y >>> 1) ^ mag01[y & 0x1];
			}
			for (; kk < N - 1; kk++) {
				y = (mt[kk] & UPPER_MASK) | (mt[kk + 1] & LOWER_MASK);
				mt[kk] = mt[kk + (M - N)] ^ (y >>> 1) ^ mag01[y & 0x1];
			}
			y = (mt[N - 1] & UPPER_MASK) | (mt[0] & LOWER_MASK);
			mt[N - 1] = mt[M - 1] ^ (y >>> 1) ^ mag01[y & 0x1];

			mti = 0;
		}

		y = mt[mti++];
		y ^= y >>> 11; // TEMPERING_SHIFT_U(y)
		y ^= (y << 7) & TEMPERING_MASK_B; // TEMPERING_SHIFT_S(y)
		y ^= (y << 15) & TEMPERING_MASK_C; // TEMPERING_SHIFT_T(y)
		y ^= (y >>> 18); // TEMPERING_SHIFT_L(y)

		return (byte) (y >>> 24);
	}

	public final boolean nextBoolean() {
		int y;

		if (mti >= N) // generate N words at one time
		{
			int kk;
			final int[] mt = this.mt; // locals are slightly faster
			final int[] mag01 = this.mag01; // locals are slightly faster

			for (kk = 0; kk < N - M; kk++) {
				y = (mt[kk] & UPPER_MASK) | (mt[kk + 1] & LOWER_MASK);
				mt[kk] = mt[kk + M] ^ (y >>> 1) ^ mag01[y & 0x1];
			}
			for (; kk < N - 1; kk++) {
				y = (mt[kk] & UPPER_MASK) | (mt[kk + 1] & LOWER_MASK);
				mt[kk] = mt[kk + (M - N)] ^ (y >>> 1) ^ mag01[y & 0x1];
			}
			y = (mt[N - 1] & UPPER_MASK) | (mt[0] & LOWER_MASK);
			mt[N - 1] = mt[M - 1] ^ (y >>> 1) ^ mag01[y & 0x1];

			mti = 0;
		}

		y = mt[mti++];
		y ^= y >>> 11; // TEMPERING_SHIFT_U(y)
		y ^= (y << 7) & TEMPERING_MASK_B; // TEMPERING_SHIFT_S(y)
		y ^= (y << 15) & TEMPERING_MASK_C; // TEMPERING_SHIFT_T(y)
		y ^= (y >>> 18); // TEMPERING_SHIFT_L(y)

		return (boolean) ((y >>> 31) != 0);
	}

	public final short nextShort() {
		int y;

		if (mti >= N) // generate N words at one time
		{
			int kk;
			final int[] mt = this.mt; // locals are slightly faster
			final int[] mag01 = this.mag01; // locals are slightly faster

			for (kk = 0; kk < N - M; kk++) {
				y = (mt[kk] & UPPER_MASK) | (mt[kk + 1] & LOWER_MASK);
				mt[kk] = mt[kk + M] ^ (y >>> 1) ^ mag01[y & 0x1];
			}
			for (; kk < N - 1; kk++) {
				y = (mt[kk] & UPPER_MASK) | (mt[kk + 1] & LOWER_MASK);
				mt[kk] = mt[kk + (M - N)] ^ (y >>> 1) ^ mag01[y & 0x1];
			}
			y = (mt[N - 1] & UPPER_MASK) | (mt[0] & LOWER_MASK);
			mt[N - 1] = mt[M - 1] ^ (y >>> 1) ^ mag01[y & 0x1];

			mti = 0;
		}

		y = mt[mti++];
		y ^= y >>> 11; // TEMPERING_SHIFT_U(y)
		y ^= (y << 7) & TEMPERING_MASK_B; // TEMPERING_SHIFT_S(y)
		y ^= (y << 15) & TEMPERING_MASK_C; // TEMPERING_SHIFT_T(y)
		y ^= (y >>> 18); // TEMPERING_SHIFT_L(y)

		return (short) (y >>> 16);
	}

	public final long nextLong() {

		int y;
		int z;

		if (mti >= N) // generate N words at one time
		{
			int kk;
			final int[] mt = this.mt; // locals are slightly faster
			final int[] mag01 = this.mag01; // locals are slightly faster

			for (kk = 0; kk < N - M; kk++) {
				y = (mt[kk] & UPPER_MASK) | (mt[kk + 1] & LOWER_MASK);
				mt[kk] = mt[kk + M] ^ (y >>> 1) ^ mag01[y & 0x1];
			}
			for (; kk < N - 1; kk++) {
				y = (mt[kk] & UPPER_MASK) | (mt[kk + 1] & LOWER_MASK);
				mt[kk] = mt[kk + (M - N)] ^ (y >>> 1) ^ mag01[y & 0x1];
			}
			y = (mt[N - 1] & UPPER_MASK) | (mt[0] & LOWER_MASK);
			mt[N - 1] = mt[M - 1] ^ (y >>> 1) ^ mag01[y & 0x1];

			mti = 0;
		}

		y = mt[mti++];
		y ^= y >>> 11; // TEMPERING_SHIFT_U(y)
		y ^= (y << 7) & TEMPERING_MASK_B; // TEMPERING_SHIFT_S(y)
		y ^= (y << 15) & TEMPERING_MASK_C; // TEMPERING_SHIFT_T(y)
		y ^= (y >>> 18); // TEMPERING_SHIFT_L(y)

		if (mti >= N) // generate N words at one time
		{
			int kk;
			final int[] mt = this.mt; // locals are slightly faster
			final int[] mag01 = this.mag01; // locals are slightly faster

			for (kk = 0; kk < N - M; kk++) {
				z = (mt[kk] & UPPER_MASK) | (mt[kk + 1] & LOWER_MASK);
				mt[kk] = mt[kk + M] ^ (z >>> 1) ^ mag01[z & 0x1];
			}
			for (; kk < N - 1; kk++) {
				z = (mt[kk] & UPPER_MASK) | (mt[kk + 1] & LOWER_MASK);
				mt[kk] = mt[kk + (M - N)] ^ (z >>> 1) ^ mag01[z & 0x1];
			}
			z = (mt[N - 1] & UPPER_MASK) | (mt[0] & LOWER_MASK);
			mt[N - 1] = mt[M - 1] ^ (z >>> 1) ^ mag01[z & 0x1];

			mti = 0;
		}

		z = mt[mti++];
		z ^= z >>> 11; // TEMPERING_SHIFT_U(z)
		z ^= (z << 7) & TEMPERING_MASK_B; // TEMPERING_SHIFT_S(z)
		z ^= (z << 15) & TEMPERING_MASK_C; // TEMPERING_SHIFT_T(z)
		z ^= (z >>> 18); // TEMPERING_SHIFT_L(z)

		return (((long) y) << 32) + (long) z;
	}

	/**
	 * Returns a random double in the half-open range from [0.0,1.0). Thus 0.0
	 * is a valid result but 1.0 is not.
	 */
	public final double nextDouble() {

		// ///////////////// GENERATE FUNCTION /////////////////////
		int l;
		int r;

		if (mti >= N) // generate N words at one time
		{
			int y;
			int kk;
			final int[] mt = this.mt; // locals are slightly faster
			final int[] mag01 = this.mag01; // locals are slightly
											// faster

			for (kk = 0; kk < N - M; kk++) {
				y = (mt[kk] & UPPER_MASK) | (mt[kk + 1] & LOWER_MASK);
				mt[kk] = mt[kk + M] ^ (y >>> 1) ^ mag01[y & 0x1];
			}
			for (; kk < N - 1; kk++) {
				y = (mt[kk] & UPPER_MASK) | (mt[kk + 1] & LOWER_MASK);
				mt[kk] = mt[kk + (M - N)] ^ (y >>> 1) ^ mag01[y & 0x1];
			}
			y = (mt[N - 1] & UPPER_MASK) | (mt[0] & LOWER_MASK);
			mt[N - 1] = mt[M - 1] ^ (y >>> 1) ^ mag01[y & 0x1];

			mti = 0;

		}

		l = mt[mti++];
		l ^= l >>> 11; // TEMPERING_SHIFT_U(y)
		l ^= (l << 7) & TEMPERING_MASK_B; // TEMPERING_SHIFT_S(y)
		l ^= (l << 15) & TEMPERING_MASK_C; // TEMPERING_SHIFT_T(y)
		l ^= (l >>> 18); // TEMPERING_SHIFT_L(y)

		if (mti >= N) // generate N words at one time
		{
			int y;
			int kk;
			final int[] mt = this.mt; // locals are slightly faster
			final int[] mag01 = this.mag01; // locals are slightly
											// faster

			for (kk = 0; kk < N - M; kk++) {
				y = (mt[kk] & UPPER_MASK) | (mt[kk + 1] & LOWER_MASK);
				mt[kk] = mt[kk + M] ^ (y >>> 1) ^ mag01[y & 0x1];
			}
			for (; kk < N - 1; kk++) {
				y = (mt[kk] & UPPER_MASK) | (mt[kk + 1] & LOWER_MASK);
				mt[kk] = mt[kk + (M - N)] ^ (y >>> 1) ^ mag01[y & 0x1];
			}
			y = (mt[N - 1] & UPPER_MASK) | (mt[0] & LOWER_MASK);
			mt[N - 1] = mt[M - 1] ^ (y >>> 1) ^ mag01[y & 0x1];

			mti = 0;
		}

		r = mt[mti++];
		r ^= r >>> 11; // TEMPERING_SHIFT_U(y)
		r ^= (r << 7) & TEMPERING_MASK_B; // TEMPERING_SHIFT_S(y)
		r ^= (r << 15) & TEMPERING_MASK_C; // TEMPERING_SHIFT_T(y)
		r ^= (r >>> 18); // TEMPERING_SHIFT_L(y)

		return ((((long) (l >>> 6)) << 27) + (r >>> 5)) / (double) (1L << 53);
	}

	// final double nextGaussian() {
	// if (__haveNextNextGaussian) {
	// __haveNextNextGaussian = false;
	// return __nextNextGaussian;
	// } else {
	// double v1, v2, s;
	// do {
	// int y;
	// int z;
	// int a;
	// int b;
	//
	// if (mti >= N) // generate N words at one time
	// {
	// int kk;
	// final int[] mt = this.mt; // locals are slightly faster
	// final int[] mag01 = this.mag01; // locals are slightly
	// // faster
	//
	// for (kk = 0; kk < N - M; kk++) {
	// y = (mt[kk] & UPPER_MASK) | (mt[kk + 1] & LOWER_MASK);
	// mt[kk] = mt[kk + M] ^ (y >>> 1) ^ mag01[y & 0x1];
	// }
	// for (; kk < N - 1; kk++) {
	// y = (mt[kk] & UPPER_MASK) | (mt[kk + 1] & LOWER_MASK);
	// mt[kk] = mt[kk + (M - N)] ^ (y >>> 1) ^ mag01[y & 0x1];
	// }
	// y = (mt[N - 1] & UPPER_MASK) | (mt[0] & LOWER_MASK);
	// mt[N - 1] = mt[M - 1] ^ (y >>> 1) ^ mag01[y & 0x1];
	//
	// mti = 0;
	// }
	//
	// y = mt[mti++];
	// y ^= y >>> 11; // TEMPERING_SHIFT_U(y)
	// y ^= (y << 7) & TEMPERING_MASK_B; // TEMPERING_SHIFT_S(y)
	// y ^= (y << 15) & TEMPERING_MASK_C; // TEMPERING_SHIFT_T(y)
	// y ^= (y >>> 18); // TEMPERING_SHIFT_L(y)
	//
	// if (mti >= N) // generate N words at one time
	// {
	// int kk;
	// final int[] mt = this.mt; // locals are slightly faster
	// final int[] mag01 = this.mag01; // locals are slightly
	// // faster
	//
	// for (kk = 0; kk < N - M; kk++) {
	// z = (mt[kk] & UPPER_MASK) | (mt[kk + 1] & LOWER_MASK);
	// mt[kk] = mt[kk + M] ^ (z >>> 1) ^ mag01[z & 0x1];
	// }
	// for (; kk < N - 1; kk++) {
	// z = (mt[kk] & UPPER_MASK) | (mt[kk + 1] & LOWER_MASK);
	// mt[kk] = mt[kk + (M - N)] ^ (z >>> 1) ^ mag01[z & 0x1];
	// }
	// z = (mt[N - 1] & UPPER_MASK) | (mt[0] & LOWER_MASK);
	// mt[N - 1] = mt[M - 1] ^ (z >>> 1) ^ mag01[z & 0x1];
	//
	// mti = 0;
	// }
	//
	// z = mt[mti++];
	// z ^= z >>> 11; // TEMPERING_SHIFT_U(z)
	// z ^= (z << 7) & TEMPERING_MASK_B; // TEMPERING_SHIFT_S(z)
	// z ^= (z << 15) & TEMPERING_MASK_C; // TEMPERING_SHIFT_T(z)
	// z ^= (z >>> 18); // TEMPERING_SHIFT_L(z)
	//
	// if (mti >= N) // generate N words at one time
	// {
	// int kk;
	// final int[] mt = this.mt; // locals are slightly faster
	// final int[] mag01 = this.mag01; // locals are slightly
	// // faster
	//
	// for (kk = 0; kk < N - M; kk++) {
	// a = (mt[kk] & UPPER_MASK) | (mt[kk + 1] & LOWER_MASK);
	// mt[kk] = mt[kk + M] ^ (a >>> 1) ^ mag01[a & 0x1];
	// }
	// for (; kk < N - 1; kk++) {
	// a = (mt[kk] & UPPER_MASK) | (mt[kk + 1] & LOWER_MASK);
	// mt[kk] = mt[kk + (M - N)] ^ (a >>> 1) ^ mag01[a & 0x1];
	// }
	// a = (mt[N - 1] & UPPER_MASK) | (mt[0] & LOWER_MASK);
	// mt[N - 1] = mt[M - 1] ^ (a >>> 1) ^ mag01[a & 0x1];
	//
	// mti = 0;
	// }
	//
	// a = mt[mti++];
	// a ^= a >>> 11; // TEMPERING_SHIFT_U(a)
	// a ^= (a << 7) & TEMPERING_MASK_B; // TEMPERING_SHIFT_S(a)
	// a ^= (a << 15) & TEMPERING_MASK_C; // TEMPERING_SHIFT_T(a)
	// a ^= (a >>> 18); // TEMPERING_SHIFT_L(a)
	//
	// if (mti >= N) // generate N words at one time
	// {
	// int kk;
	// final int[] mt = this.mt; // locals are slightly faster
	// final int[] mag01 = this.mag01; // locals are slightly
	// // faster
	//
	// for (kk = 0; kk < N - M; kk++) {
	// b = (mt[kk] & UPPER_MASK) | (mt[kk + 1] & LOWER_MASK);
	// mt[kk] = mt[kk + M] ^ (b >>> 1) ^ mag01[b & 0x1];
	// }
	// for (; kk < N - 1; kk++) {
	// b = (mt[kk] & UPPER_MASK) | (mt[kk + 1] & LOWER_MASK);
	// mt[kk] = mt[kk + (M - N)] ^ (b >>> 1) ^ mag01[b & 0x1];
	// }
	// b = (mt[N - 1] & UPPER_MASK) | (mt[0] & LOWER_MASK);
	// mt[N - 1] = mt[M - 1] ^ (b >>> 1) ^ mag01[b & 0x1];
	//
	// mti = 0;
	// }
	//
	// b = mt[mti++];
	// b ^= b >>> 11; // TEMPERING_SHIFT_U(b)
	// b ^= (b << 7) & TEMPERING_MASK_B; // TEMPERING_SHIFT_S(b)
	// b ^= (b << 15) & TEMPERING_MASK_C; // TEMPERING_SHIFT_T(b)
	// b ^= (b >>> 18); // TEMPERING_SHIFT_L(b)
	//
	// /*
	// * derived from nextDouble documentation in jdk 1.2 docs, see
	// * top
	// */
	// v1 = 2 * (((((long) (y >>> 6)) << 27) + (z >>> 5)) / (double) (1L << 53))
	// - 1;
	// v2 = 2 * (((((long) (a >>> 6)) << 27) + (b >>> 5)) / (double) (1L << 53))
	// - 1;
	// s = v1 * v1 + v2 * v2;
	// } while (s >= 1 || s == 0);
	// double multiplier = /* Strict */Math.sqrt(-2
	// * /* Strict */Math.log(s) / s);
	// __nextNextGaussian = v2 * multiplier;
	// __haveNextNextGaussian = true;
	// return v1 * multiplier;
	// }
	// }

	/**
	 * Returns a random float in the half-open range from [0.0f,1.0f). Thus 0.0f
	 * is a valid result but 1.0f is not.
	 */
	public float nextFloat() {

		int y;

		if (mti >= N) // generate N words at one time
		{
			int kk;
			final int[] mt = this.mt; // locals are slightly faster
			final int[] mag01 = this.mag01; // locals are slightly faster

			for (kk = 0; kk < N - M; kk++) {
				y = (mt[kk] & UPPER_MASK) | (mt[kk + 1] & LOWER_MASK);
				mt[kk] = mt[kk + M] ^ (y >>> 1) ^ mag01[y & 0x1];
			}
			for (; kk < N - 1; kk++) {
				y = (mt[kk] & UPPER_MASK) | (mt[kk + 1] & LOWER_MASK);
				mt[kk] = mt[kk + (M - N)] ^ (y >>> 1) ^ mag01[y & 0x1];
			}
			y = (mt[N - 1] & UPPER_MASK) | (mt[0] & LOWER_MASK);
			mt[N - 1] = mt[M - 1] ^ (y >>> 1) ^ mag01[y & 0x1];

			mti = 0;
		}

		y = mt[mti++];
		y ^= y >>> 11; // TEMPERING_SHIFT_U(y)
		y ^= (y << 7) & TEMPERING_MASK_B; // TEMPERING_SHIFT_S(y)
		y ^= (y << 15) & TEMPERING_MASK_C; // TEMPERING_SHIFT_T(y)
		y ^= (y >>> 18); // TEMPERING_SHIFT_L(y)

		return (y >>> 8) / ((float) (1 << 24));
	}

	@Override
	public final int[] mag01() {
		return mag01;
	}

	@Override
	public final int[] mt() {
		return mt;
	}

	@Override
	public final int mti() {
		return mti;
	}

	@Override
	public final String toString() {
		return PRNG.MT.name();
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
	public boolean equals(Object obj) {
		if (obj == null)
			return false;

		if (!this.isOpen())
			return false;

		if (!(obj instanceof Pseudorandomness))
			return false;

		if (!((Pseudorandomness) obj).isOpen())
			return false;

		if (this == obj)
			return true;

		if (!(obj instanceof Engine.MT))
			return false;

		Engine.MT that = (Engine.MT) obj;

		if (this.mti() != that.mti())
			return false;

		if (!(that.mag01() instanceof int[]))
			return false; // possibly MT64.

		final int mag01[] = this.mag01();
		final int mag02[] = (int[]) that.mag01();

		for (int x = 0; x < mag01.length; x++)
			if (mag01[x] != mag02[x])
				return false;

		if (!(that.mt() instanceof int[]))
			return false; // possibly MT64.

		final int mt1[] = this.mt();
		final int mt2[] = (int[]) that.mt();

		for (int x = 0; x < mt1.length; x++)
			if (mt1[x] != mt2[x])
				return false;

		return true;
	}

	@Override
	public final Pseudorandomness copy() {
		MT copy = new MT();
		copy.reseed((ByteBuffer) this.mark.clear());

		copy.mti = this.mti;

		System.arraycopy(this.mag01, 0, copy.mag01, 0, this.mag01.length);
		System.arraycopy(this.mt, 0, copy.mt, 0, this.mt.length);

		return copy;
	}

	@Override
	public final int minlen() {
		return INT_SIZE_BYTES;
	}

	/**
	 * Shared wrapper around MT
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
		private final MT _this;

		public Shared() {
			_this = MT.this;
			idx.set(_this.mti);
			assert shared == true;
		}

		@Override
		protected int seedlen() {
			return MT.this.seedlen();
		}

		// ///////////////////////////////////////////////////////////
		// /////////////// PRNG MECHANISMS ///////////////////////////
		// ///////////////////////////////////////////////////////////

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

		@Override
		public int[] mag01() {
			return _this.mag01();
		}

		@Override
		public int[] mt() {
			return _this.mt();
		}

		@Override
		public int mti() {
			return _this.mti();
		}

		// ///////////////////////////////////////////////////////////
		// /////////////// PRNG GENERATE FUNCTIONS ///////////////////
		// ///////////////////////////////////////////////////////////

		@Override
		public final int read(ByteBuffer buffer) {
			if (!isOpen())
				throw new NonReadableChannelException();

			final int numBytes = buffer.remaining();

			try {
				lock.lock();
				_this.mti = acquireCounter();
				nextInt = nextLong = true; // clear intermediate state

				_this.read(buffer);

				releaseCounter(_this.mti); // restore counter to global state
			} finally {
				lock.unlock();
			}

			return numBytes - buffer.remaining() /* should be zero */;
		}

		@Override
		public final int read(IntBuffer intBuffer) {
			if (!isOpen())
				throw new NonReadableChannelException();

			final int numBytes = intBuffer.remaining();

			try {
				lock.lock();
				_this.mti = acquireCounter();
				nextInt = nextLong = true; // clear intermediate state

				_this.read(intBuffer);

				releaseCounter(_this.mti); // restore counter to global state
			} finally {
				lock.unlock();
			}

			return numBytes - intBuffer.remaining() /* should be zero */;
		}

		@Override
		public final int read(FloatBuffer floatBuffer) {
			if (!isOpen())
				throw new NonReadableChannelException();

			final int numBytes = floatBuffer.remaining();

			try {
				lock.lock();

				_this.mti = acquireCounter();
				nextInt = nextLong = true; // clear intermediate state

				_this.read(floatBuffer);

				releaseCounter(_this.mti); // restore counter to global state
			} finally {
				lock.unlock();
			}

			return numBytes - floatBuffer.remaining() /* should be zero */;
		}

		@Override
		public final int read(LongBuffer longBuffer) {
			if (!isOpen())
				throw new NonReadableChannelException();

			final int numBytes = longBuffer.remaining();

			try {
				lock.lock();
				_this.mti = acquireCounter();
				nextInt = nextLong = true; // clear intermediate state

				_this.read(longBuffer);

				releaseCounter(_this.mti); // restore counter to global state
			} finally {
				lock.unlock();
			}

			return numBytes - longBuffer.remaining() /* should be zero */;
		}

		@Override
		public final int read(DoubleBuffer doubleBuffer) {
			if (!isOpen())
				throw new NonReadableChannelException();

			final int numBytes = doubleBuffer.remaining();

			try {
				lock.lock();
				_this.mti = acquireCounter();
				nextInt = nextLong = true; // clear intermediate state

				_this.read(doubleBuffer);

				releaseCounter(_this.mti); // restore counter to global state
			} finally {
				lock.unlock();
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
			return MT.this.toString();
		}

		@Override
		public final Pseudorandomness copy() {
			if (!isOpen())
				throw new NonReadableChannelException();

			try {
				lock.lock();

				MT mt = (MT) _this.copy();

				MT.Shared sharedCopy = mt.new Shared();
				{ // copy intermediate state
					sharedCopy.nextByte = this.nextByte;
					sharedCopy.nextShort = this.nextShort;
					sharedCopy.nextInt = this.nextInt;
					sharedCopy.nextLong = this.nextLong;

					sharedCopy.newByte = this.newByte;
					sharedCopy.newShort = this.newShort;

					sharedCopy.mask8 = this.mask8;

					sharedCopy.word8 = this.word8;
					sharedCopy.word16 = this.word16;
					sharedCopy.word32 = this.word32;
				}
				return sharedCopy;

			} finally {
				lock.unlock();
			}
		}

		// ///////////////////////////////////////////////
		// /////////////// PRNG nextXXX //////////////////
		// ///////////////////////////////////////////////

		private int mask8 = 1;

		// //////////////// INTERMEDIATE STATE/// ////////////////////
		private volatile byte word8; // eight bits
		private volatile short word16;; // two bytes
		private volatile int word32; // two shorts

		private volatile boolean newByte = true; // we need new byte?
		private volatile boolean newShort = true; // we need new short?

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

			int y;
			nextInt = true;

			// obtain value from internal buffer
			for (;;) {

				// get current index;
				int mtI = idx.get();
				int next = mtI + 1;

				// assert mtI == _this.mti;

				if (mtI < 0) // can't generate, buffer is not ready
					continue;

				if (mtI >= N) { // update internal buffer

					if (!idx.compareAndSet(mtI, -1)) // try acquire lock
						continue; // counter state is changed

					// /////////////// GENERATE FUNCTION ////////////////////
					int kk;
					final int[] mt = _this.mt; // locals are slightly faster
					final int[] mag01 = _this.mag01; // locals are slightly
														// faster
					for (kk = 0; kk < N - M; kk++) {
						y = (mt[kk] & UPPER_MASK) | (mt[kk + 1] & LOWER_MASK);
						mt[kk] = mt[kk + M] ^ (y >>> 1) ^ mag01[y & 0x1];
					}
					for (; kk < N - 1; kk++) {
						y = (mt[kk] & UPPER_MASK) | (mt[kk + 1] & LOWER_MASK);
						mt[kk] = mt[kk + (M - N)] ^ (y >>> 1) ^ mag01[y & 0x1];
					}
					y = (mt[N - 1] & UPPER_MASK) | (mt[0] & LOWER_MASK);
					mt[N - 1] = mt[M - 1] ^ (y >>> 1) ^ mag01[y & 0x1];
					// /////////////// GENERATE FUNCTION //////////////////////

					y = mt[0];
					idx.set(1); // reset state from -1

					break;
				}

				y = mt[mtI];

				if (idx.compareAndSet(mtI, next)) {
					break;
				}
			}

			y ^= y >>> 11; // TEMPERING_SHIFT_U(y)
			y ^= (y << 7) & TEMPERING_MASK_B; // TEMPERING_SHIFT_S(y)
			y ^= (y << 15) & TEMPERING_MASK_C; // TEMPERING_SHIFT_T(y)
			y ^= (y >>> 18); // TEMPERING_SHIFT_L(y)

			return y;
		}

		@Override
		public final float nextFloat() {
			if (!isOpen())
				throw new NonReadableChannelException();

			int y;
			nextInt = true;

			// obtain value from internal buffer
			for (;;) {

				// get current index;
				int mtI = idx.get();
				int next = mtI + 1;

				if (mtI < 0) // can't generate, buffer is not ready
					continue;

				if (mtI >= N) { // update internal buffer

					if (!idx.compareAndSet(mtI, -1)) // try acquire lock
						continue; // counter state is changed

					// /////////////// GENERATE FUNCTION ////////////////////
					int kk;
					final int[] mt = _this.mt; // locals are slightly faster
					final int[] mag01 = _this.mag01; // locals are slightly
														// faster
					for (kk = 0; kk < N - M; kk++) {
						y = (mt[kk] & UPPER_MASK) | (mt[kk + 1] & LOWER_MASK);
						mt[kk] = mt[kk + M] ^ (y >>> 1) ^ mag01[y & 0x1];
					}
					for (; kk < N - 1; kk++) {
						y = (mt[kk] & UPPER_MASK) | (mt[kk + 1] & LOWER_MASK);
						mt[kk] = mt[kk + (M - N)] ^ (y >>> 1) ^ mag01[y & 0x1];
					}
					y = (mt[N - 1] & UPPER_MASK) | (mt[0] & LOWER_MASK);
					mt[N - 1] = mt[M - 1] ^ (y >>> 1) ^ mag01[y & 0x1];
					// /////////////// GENERATE FUNCTION //////////////////////

					y = mt[0];
					idx.set(1); // reset state from -1

					break;
				}

				y = mt[mtI];

				if (idx.compareAndSet(mtI, next)) {
					break;
				}
			}

			y ^= y >>> 11; // TEMPERING_SHIFT_U(y)
			y ^= (y << 7) & TEMPERING_MASK_B; // TEMPERING_SHIFT_S(y)
			y ^= (y << 15) & TEMPERING_MASK_C; // TEMPERING_SHIFT_T(y)
			y ^= (y >>> 18); // TEMPERING_SHIFT_L(y)

			return (y >>> 8) / ((float) (1 << 24));
		}

		@Override
		public long nextLong() {
			if (!isOpen())
				throw new NonReadableChannelException();

			int l;
			int r;
			nextLong = true;

			// obtain value from internal buffer
			for (;;) {

				// get current index;
				int mtI = idx.get();
				int next = mtI + 2;

				if (mtI < 0) // can't generate, buffer is not ready
					continue;

				if (mtI == (N - 1)) { // only one 32 word in buffer

					if (!idx.compareAndSet(mtI, -1)) // try acquire lock
						continue; // counter state is changed

					l = mt[mtI++];

					// /////////////// GENERATE FUNCTION ////////////////////
					{
						int kk, y;
						final int[] mt = _this.mt; // locals are slightly faster
						final int[] mag01 = _this.mag01; // locals are slightly
															// faster
						for (kk = 0; kk < N - M; kk++) {
							y = (mt[kk] & UPPER_MASK)
									| (mt[kk + 1] & LOWER_MASK);
							mt[kk] = mt[kk + M] ^ (y >>> 1) ^ mag01[y & 0x1];
						}
						for (; kk < N - 1; kk++) {
							y = (mt[kk] & UPPER_MASK)
									| (mt[kk + 1] & LOWER_MASK);
							mt[kk] = mt[kk + (M - N)] ^ (y >>> 1)
									^ mag01[y & 0x1];
						}
						y = (mt[N - 1] & UPPER_MASK) | (mt[0] & LOWER_MASK);
						mt[N - 1] = mt[M - 1] ^ (y >>> 1) ^ mag01[y & 0x1];
						mtI = 0;
					}

					r = mt[0];
					idx.set(1); // reset from -1 state
					break;
				}

				if (mtI >= N) { // update internal buffer

					if (!idx.compareAndSet(mtI, -1)) // try acquire lock
						continue; // counter state is changed

					{
						int kk, y;
						final int[] mt = _this.mt; // locals are slightly faster
						final int[] mag01 = _this.mag01; // locals are slightly
															// faster
						for (kk = 0; kk < N - M; kk++) {
							y = (mt[kk] & UPPER_MASK)
									| (mt[kk + 1] & LOWER_MASK);
							mt[kk] = mt[kk + M] ^ (y >>> 1) ^ mag01[y & 0x1];
						}
						for (; kk < N - 1; kk++) {
							y = (mt[kk] & UPPER_MASK)
									| (mt[kk + 1] & LOWER_MASK);
							mt[kk] = mt[kk + (M - N)] ^ (y >>> 1)
									^ mag01[y & 0x1];
						}
						y = (mt[N - 1] & UPPER_MASK) | (mt[0] & LOWER_MASK);
						mt[N - 1] = mt[M - 1] ^ (y >>> 1) ^ mag01[y & 0x1];
						mtI = 0;
					}

					l = mt[0];
					r = mt[1];

					idx.set(2); // reset state from -1
					break;
				}

				// normal generation
				l = mt[mtI];
				r = mt[mtI + 1];

				if (idx.compareAndSet(mtI, next)) {
					break;
				}
			}

			l ^= l >>> 11; // TEMPERING_SHIFT_U(y)
			l ^= (l << 7) & TEMPERING_MASK_B; // TEMPERING_SHIFT_S(y)
			l ^= (l << 15) & TEMPERING_MASK_C; // TEMPERING_SHIFT_T(y)
			l ^= (l >>> 18); // TEMPERING_SHIFT_L(y)

			r ^= r >>> 11; // TEMPERING_SHIFT_U(y)
			r ^= (r << 7) & TEMPERING_MASK_B; // TEMPERING_SHIFT_S(y)
			r ^= (r << 15) & TEMPERING_MASK_C; // TEMPERING_SHIFT_T(y)
			r ^= (r >>> 18); // TEMPERING_SHIFT_L(y)

			return (((long) l) << 32) + (long) r;
		}

		@Override
		public final double nextDouble() {
			if (!isOpen())
				throw new NonReadableChannelException();

			int l;
			int r;
			nextLong = true;

			// obtain value from internal buffer
			for (;;) {

				// get current index;
				int mtI = idx.get();
				int next = mtI + 2;

				if (mtI < 0) // can't generate, buffer is not ready
					continue;

				if (mtI == (N - 1)) { // only one 32 word in buffer

					if (!idx.compareAndSet(mtI, -1)) // try acquire lock
						continue; // counter state is changed

					l = _this.mt[mtI++];

					// /////////////// GENERATE FUNCTION ////////////////////
					{
						int kk, y;
						final int[] mt = _this.mt; // locals are slightly faster
						final int[] mag01 = _this.mag01; // locals are slightly
															// faster
						for (kk = 0; kk < N - M; kk++) {
							y = (mt[kk] & UPPER_MASK)
									| (mt[kk + 1] & LOWER_MASK);
							mt[kk] = mt[kk + M] ^ (y >>> 1) ^ mag01[y & 0x1];
						}
						for (; kk < N - 1; kk++) {
							y = (mt[kk] & UPPER_MASK)
									| (mt[kk + 1] & LOWER_MASK);
							mt[kk] = mt[kk + (M - N)] ^ (y >>> 1)
									^ mag01[y & 0x1];
						}
						y = (mt[N - 1] & UPPER_MASK) | (mt[0] & LOWER_MASK);
						mt[N - 1] = mt[M - 1] ^ (y >>> 1) ^ mag01[y & 0x1];
						mtI = 0;
					}

					r = mt[0];
					idx.set(1); // reset from -1 state
					break;
				}

				if (mtI >= N) { // update internal buffer

					if (!idx.compareAndSet(mtI, -1)) // try acquire lock
						continue; // counter state is changed

					{
						int kk, y;
						final int[] mt = _this.mt; // locals are slightly faster
						final int[] mag01 = _this.mag01; // locals are slightly
															// faster
						for (kk = 0; kk < N - M; kk++) {
							y = (mt[kk] & UPPER_MASK)
									| (mt[kk + 1] & LOWER_MASK);
							mt[kk] = mt[kk + M] ^ (y >>> 1) ^ mag01[y & 0x1];
						}
						for (; kk < N - 1; kk++) {
							y = (mt[kk] & UPPER_MASK)
									| (mt[kk + 1] & LOWER_MASK);
							mt[kk] = mt[kk + (M - N)] ^ (y >>> 1)
									^ mag01[y & 0x1];
						}
						y = (mt[N - 1] & UPPER_MASK) | (mt[0] & LOWER_MASK);
						mt[N - 1] = mt[M - 1] ^ (y >>> 1) ^ mag01[y & 0x1];
						mtI = 0;
					}

					l = mt[0];
					r = mt[1];

					idx.set(2); // reset state from -1
					break;
				}

				// normal generation
				l = mt[mtI];
				r = mt[mtI + 1];

				if (idx.compareAndSet(mtI, next)) {
					break;
				}
			}

			l ^= l >>> 11; // TEMPERING_SHIFT_U(y)
			l ^= (l << 7) & TEMPERING_MASK_B; // TEMPERING_SHIFT_S(y)
			l ^= (l << 15) & TEMPERING_MASK_C; // TEMPERING_SHIFT_T(y)
			l ^= (l >>> 18); // TEMPERING_SHIFT_L(y)

			r ^= r >>> 11; // TEMPERING_SHIFT_U(y)
			r ^= (r << 7) & TEMPERING_MASK_B; // TEMPERING_SHIFT_S(y)
			r ^= (r << 15) & TEMPERING_MASK_C; // TEMPERING_SHIFT_T(y)
			r ^= (r >>> 18); // TEMPERING_SHIFT_L(y)

			return ((((long) (l >>> 6)) << 27) + (r >>> 5))
					/ (double) (1L << 53);
		}
	}
}