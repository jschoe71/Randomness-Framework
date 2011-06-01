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

final class SFMT extends PseudorandomnessEngine implements Engine.SFMT,
		Pseudorandomness.Multiperiodical {
	// Magic Numbers from original C version.
	// ////////////////////////////////////////////////////////////

	/**
	 * 
	 */
	private static final long serialVersionUID = -7059168589858378873L;

	/**
	 * Mersenne Exponent. The period of the sequence is a multiple of 2<sup>
	 * <code>MEXP</code></sup> &minus; 1. If you adapt this code to support a
	 * different exponent, you must change many of the other constants here as
	 * well; consult the original C code.
	 */
	private final static int MEXP = 19937;

	/**
	 * The SFMT generator has an internal state array of 128-bit integers, and
	 * <code>N</code> is its size.
	 */
	private final static int N = MEXP / 128 + 1;

	/**
	 * <code>N32</code> is the size of internal state array when regarded as an
	 * array of 32-bit integers.
	 */
	private final static int N32 = N * 4;

	/**
	 * The pick up position of the array.
	 */
	private final static int POS1 = 122;

	/**
	 * The parameter of shift left as four 32-bit registers.
	 */
	private final static int SL1 = 18;

	/**
	 * The parameter of shift left as one 128-bit register. The 128-bit integer
	 * is shifted by <code>SL2 * 8</code> bits.
	 */
	private final static int SL2 = 1;

	/**
	 * The parameter of shift right as four 32-bit registers.
	 */
	private final static int SR1 = 11;

	/**
	 * The parameter of shift right as one 128-bit register. The 128-bit integer
	 * is shifted by <code>SL2 * 8</code> bits.
	 */
	final static int SR2 = 1;

	/**
	 * A bitmask parameter, used in the recursion to break symmetry of SIMD.
	 */
	final static int MSK1 = 0xdfffffef;

	/**
	 * A bitmask parameter, used in the recursion to break symmetry of SIMD.
	 */
	final static int MSK2 = 0xddfecb7f;

	/**
	 * A bitmask parameter, used in the recursion to break symmetry of SIMD.
	 */
	final static int MSK3 = 0xbffaffff;

	/**
	 * A bitmask parameter, used in the recursion to break symmetry of SIMD.
	 */
	final static int MSK4 = 0xbffffff6;

	/**
	 * Part of a 128-bit period certification vector.
	 */
	final static int PARITY1 = 0x00000001;

	/**
	 * Part of a 128-bit period certification vector.
	 */
	final static int PARITY2 = 0x00000000;

	/**
	 * Part of a 128-bit period certification vector.
	 */
	final static int PARITY3 = 0x00000000;

	/**
	 * Part of a 128-bit period certification vector.
	 */
	final static int PARITY4 = 0x13c9e684;

	/**
	 * A parity check vector which certifies the period of 2<sup>{@link #MEXP}
	 * </sup>.
	 */
	final static int parity[] = { PARITY1, PARITY2, PARITY3, PARITY4 };

	/**
	 * A number mixed with the time of day to provide a unique seed to each
	 * generator of this type allocated.
	 */
	static long uniquifier = 314159265358979L;

	// Instance variables
	// //////////////////////////////////////////////////////////

	/**
	 * The internal state array. Blocks of four consecutive <code>int</code>s
	 * are often treated as a single 128-bit integer that is
	 * little-endian&mdash;that is, its low-order bits are at lower indices in
	 * the array, and high-order bits at higher indices.
	 */
	private final int[] sfmt = new int[N32];

	/**
	 * Index counter of the next <code>int</code> to return from {@link #next}.
	 */
	private int idx = N32;

	public SFMT() {
		this.reset();
	}

	@Override
	protected final void instantiate(ByteBuffer seed) {
		final int rem = seed.remaining(); // number of readable bytes

		// ////////////////// INSTANTIATE FUNCTION ////////////////////////
		if (rem == INT_SIZE_BYTES) { // go to init_genrand with 4-byte seed
			initGenRandom32(seed.getInt());
		} else {

			// convert seed bytes to int array
			final IntBuffer intBuffer = seed.asIntBuffer();
			int[] seed32 = new int[intBuffer.remaining()];
			seed.asIntBuffer().get(seed32);

			/*
			 * Initializes the internal state array with an array of 32-bit
			 * integers.
			 */
			@SuppressWarnings("unused")
			int lag = N32 >= 623 ? 11 : N32 >= 68 ? 7 : N32 >= 39 ? 5 : 3, mid = (N32 - lag) / 2;
			for (int i = sfmt.length - 1; i >= 0; i--)
				sfmt[i] = 0x8b8b8b8b;

			int count = seed32.length >= N32 ? seed32.length : N32 - 1, r = func1(0x8b8b8b8b);
			sfmt[mid] += r;
			r += seed32.length;
			sfmt[mid + lag] += r;
			sfmt[0] = r;
			int i = 1, j = 0;
			for (; j < count && j < seed32.length; j++) {
				r = func1(sfmt[i] ^ sfmt[(i + mid) % N32]
						^ sfmt[(i + N32 - 1) % N32]);
				sfmt[(i + mid) % N32] += r;
				r += seed32[j] + i;
				sfmt[(i + mid + lag) % N32] += r;
				sfmt[i] = r;
				i = (i + 1) % N32;
			}

			for (; j < count; j++) {
				r = func1(sfmt[i] ^ sfmt[(i + mid) % N32]
						^ sfmt[(i + N32 - 1) % N32]);
				sfmt[(i + mid) % N32] += r;
				r += i;
				sfmt[(i + mid + lag) % N32] += r;
				sfmt[i] = r;
				i = (i + 1) % N32;
			}

			for (j = 0; j < N32; j++) {
				r = func2(sfmt[i] + sfmt[(i + mid) % N32]
						+ sfmt[(i + N32 - 1) % N32]);
				sfmt[(i + mid) % N32] ^= r;
				r -= i;
				sfmt[(i + mid + lag) % N32] ^= r;
				sfmt[i] = r;
				i = (i + 1) % N32;
			}

			periodCertification();
			idx = N32;
		}
		// ////////////////// INSTANTIATE FUNCTION ////////////////////////

		// ////////////////// GENERATE FUNCTION ///////////////////////////
		if (idx >= N32) {
			final int[] sfmt = this.sfmt;

			int i = 0, r1 = 4 * (N - 2), r2 = 4 * (N - 1);
			for (; i < 4 * (N - POS1); i += 4) {
				doRecursion(sfmt, i, sfmt, i, sfmt, i + 4 * POS1, sfmt, r1,
						sfmt, r2);
				r1 = r2;
				r2 = i;
			}
			for (; i < 4 * N; i += 4) {
				doRecursion(sfmt, i, sfmt, i, sfmt, i + 4 * (POS1 - N), sfmt,
						r1, sfmt, r2);
				r1 = r2;
				r2 = i;
			}
			idx = 0;
		}
		// ////////////////// GENERATE FUNCTION ///////////////////////////
	}

	/**
	 * Initializes the internal state array with a 32-bit seed.
	 * 
	 * @param seed
	 *            32-bit seed.
	 */
	private final void initGenRandom32(int seed) {
		sfmt[0] = seed;
		for (int i = 1; i < N32; i++) {
			int prev = sfmt[i - 1];
			sfmt[i] = 1812433253 * (prev ^ (prev >>> 30)) + i;
		}
		periodCertification();
		idx = N32;
	}

	private final int generate32() {
		if (idx >= N32) {
			final int[] sfmt = this.sfmt;
			int i = 0, r1 = 4 * (N - 2), r2 = 4 * (N - 1);
			for (; i < 4 * (N - POS1); i += 4) {
				doRecursion(sfmt, i, sfmt, i, sfmt, i + 4 * POS1, sfmt, r1,
						sfmt, r2);
				r1 = r2;
				r2 = i;
			}
			for (; i < 4 * N; i += 4) {
				doRecursion(sfmt, i, sfmt, i, sfmt, i + 4 * (POS1 - N), sfmt,
						r1, sfmt, r2);
				r1 = r2;
				r2 = i;
			}
			idx = 0;
		}
		return sfmt[idx++];
	}

	@Override
	public final int read(ByteBuffer buffer) {
		final int numBytes = buffer.remaining();

		if (shared)
			return read1(buffer);

		int bytes = 0;

		for (; (numBytes - bytes) >= INT_SIZE_BYTES;) {

			if (shared && !isOpen()) // check interruption status
				return bytes; // interrupt

			// ///////////////// GENERATE FUNCTION /////////////////////
			if (idx >= N32) {
				final int[] sfmt = this.sfmt;
				int i = 0, r1 = 4 * (N - 2), r2 = 4 * (N - 1);
				for (; i < 4 * (N - POS1); i += 4) {
					doRecursion(sfmt, i, sfmt, i, sfmt, i + 4 * POS1, sfmt, r1,
							sfmt, r2);
					r1 = r2;
					r2 = i;
				}
				for (; i < 4 * N; i += 4) {
					doRecursion(sfmt, i, sfmt, i, sfmt, i + 4 * (POS1 - N),
							sfmt, r1, sfmt, r2);
					r1 = r2;
					r2 = i;
				}
				idx = 0;

				// //////////////// BLOCK MODE ///////////////////////////////
				if ((numBytes - bytes) >= (INT_SIZE_BYTES * N32)) {
					buffer.slice().asIntBuffer().put(sfmt);
					buffer.position(buffer.position() + (INT_SIZE_BYTES * N32));
					bytes += INT_SIZE_BYTES * N32; // inc bytes
					idx = N32;
					continue;
				}
				// //////////////// BLOCK MODE ///////////////////////////////
			}

			// ///////////////// GENERATE FUNCTION /////////////////////
			buffer.putInt(sfmt[idx++]);
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

	private final int read1(ByteBuffer buffer) {

		final IntBuffer intBuffer = buffer.slice().asIntBuffer();
		final int numBytes = buffer.remaining();

		this.read1(intBuffer); // PHASE 1, 2;

		// PHASE 3. SYNCHRONIZE STATES BETWEEN BUFFERS
		int bytes = intBuffer.position() * INT_SIZE_BYTES;
		buffer.position(buffer.position() + bytes);

		// PHASE 4. PUT LAST BYTES
		if (bytes < numBytes) {
			// put last bytes
			int rnd;
			if (idx >= N32) {
				rnd = generate32();
			} else {
				rnd = sfmt[idx++];
			}

			for (int n = numBytes - bytes; n-- > 0; bytes++)
				buffer.put((byte) (rnd >>> (Byte.SIZE * n)));
		}

		return numBytes - buffer.remaining() /* should be zero */;
	}

	@Override
	public final int read(IntBuffer intBuffer) {

		final int numInts = intBuffer.remaining();

		int ints = 0;

		if (!shared)
			return read1(intBuffer);

		main_loop: for (; ints < numInts;) {

			if (shared && !isOpen()) // check interruption status
				return ints; // interrupt

			// ///////////////// GENERATE FUNCTION /////////////////////
			if (idx >= N32) {
				final int[] sfmt = this.sfmt;
				int i = 0, r1 = 4 * (N - 2), r2 = 4 * (N - 1);
				for (; i < 4 * (N - POS1); i += 4) {
					doRecursion(sfmt, i, sfmt, i, sfmt, i + 4 * POS1, sfmt, r1,
							sfmt, r2);
					r1 = r2;
					r2 = i;
				}
				for (; i < 4 * N; i += 4) {
					doRecursion(sfmt, i, sfmt, i, sfmt, i + 4 * (POS1 - N),
							sfmt, r1, sfmt, r2);
					r1 = r2;
					r2 = i;
				}
				idx = 0;

				// //////////////// BLOCK MODE /////////////////////////
				if (intBuffer.remaining() >= N32) {
					intBuffer.put(sfmt);
					ints += N32;
					idx = N32;
					continue main_loop;
				}
				// //////////////// BLOCK MODE /////////////////////////
			}

			int length = Math.min(intBuffer.remaining(), (sfmt.length - idx));

			intBuffer.put(sfmt, idx, length);
			idx += length;
			ints += length;
		}

		return numInts - intBuffer.remaining() /* should be zero */;
	}

	private final int read1(IntBuffer intBuffer) {

		final int numInts = intBuffer.remaining();

		// PHASE 0. SFMT ZERO STATE
		if (idx > 0 || idx < N32) {
			intBuffer.put(this.sfmt, idx, N32 - idx);
			idx = N32; // mark zero state.
		}

		final int iterations = intBuffer.remaining() / N32; // number of N32
															// blocks

		// PHASE 1. BULK GENERATION
		if (iterations > 0) {

			for (int itr = 0; itr < iterations; itr++) {

				int i = 0, r1 = 4 * (N - 2), r2 = 4 * (N - 1);
				for (; i < 4 * (N - POS1); i += 4) {
					doRecursion(sfmt, i, sfmt, i, sfmt, i + 4 * POS1, sfmt, r1,
							sfmt, r2);
					r1 = r2;
					r2 = i;
				}
				for (; i < 4 * N; i += 4) {
					doRecursion(sfmt, i, sfmt, i, sfmt, i + 4 * (POS1 - N),
							sfmt, r1, sfmt, r2);
					r1 = r2;
					r2 = i;
				}
				idx = 0;

				intBuffer.put(sfmt);
			}
			idx = N32;
		}

		// PHASE 2. HALF-BULK GENERATION
		if (idx >= N32) { // // GENERATE FUNCTION /////////////////////////

			int i = 0, r1 = 4 * (N - 2), r2 = 4 * (N - 1);
			for (; i < 4 * (N - POS1); i += 4) {
				doRecursion(sfmt, i, sfmt, i, sfmt, i + 4 * POS1, sfmt, r1,
						sfmt, r2);
				r1 = r2;
				r2 = i;
			}
			for (; i < 4 * N; i += 4) {
				doRecursion(sfmt, i, sfmt, i, sfmt, i + 4 * (POS1 - N), sfmt,
						r1, sfmt, r2);
				r1 = r2;
				r2 = i;
			}

			int remaining = intBuffer.remaining(); // less than N32

			intBuffer.put(this.sfmt, 0, remaining);

			idx = remaining;
		}// //////////////// GENERATE FUNCTION ///////////////////////////

		return numInts - intBuffer.remaining() /* should be zero */;
	}

	@Override
	public int read(FloatBuffer floatBuffer) {

		final int numFloats = floatBuffer.remaining();

		int floats = 0;

		main_loop: for (; floats < numFloats;) {

			if (shared && !isOpen()) // check interruption status
				return floats; // interrupt

			// ///////////////// GENERATE FUNCTION /////////////////////
			if (idx >= N32) {
				final int[] sfmt = this.sfmt;
				int i = 0, r1 = 4 * (N - 2), r2 = 4 * (N - 1);
				for (; i < 4 * (N - POS1); i += 4) {
					doRecursion(sfmt, i, sfmt, i, sfmt, i + 4 * POS1, sfmt, r1,
							sfmt, r2);
					r1 = r2;
					r2 = i;
				}
				for (; i < 4 * N; i += 4) {
					doRecursion(sfmt, i, sfmt, i, sfmt, i + 4 * (POS1 - N),
							sfmt, r1, sfmt, r2);
					r1 = r2;
					r2 = i;
				}
				idx = 0;

				// //////////////// BLOCK MODE /////////////////////////
				if (floatBuffer.remaining() >= N32) {
					for (; idx < N32;) {
						floatBuffer.put((sfmt[idx++] >>> 8)
								/ ((float) (1 << 24)));

						floatBuffer.put((sfmt[idx++] >>> 8)
								/ ((float) (1 << 24)));
					}
					floats += N32;
					idx = N32;
					continue main_loop;
				}
				// //////////////// BLOCK MODE /////////////////////////
			}

			floatBuffer.put((sfmt[idx++] >>> 8) / ((float) (1 << 24)));
			floats++;

		}// //////////////// GENERATE FUNCTION ///////////////////////////

		return numFloats - floatBuffer.remaining() /* should be zero */;
	}

	@Override
	public final int read(LongBuffer longBuffer) {

		final int numLongs = longBuffer.remaining();
		final boolean even = (idx % 2) == 0; // block mode depends from oddity
												// of
												// index

		for (int longs = 0; longs < numLongs;) {

			if (shared && !isOpen()) // check interruption status
				return longs; // interrupt

			int l;
			int r;

			// ///////////////// GENERATE FUNCTION /////////////////////
			if (idx >= N32) {

				int i = 0, r1 = 4 * (N - 2), r2 = 4 * (N - 1);
				for (; i < 4 * (N - POS1); i += 4) {
					doRecursion(sfmt, i, sfmt, i, sfmt, i + 4 * POS1, sfmt, r1,
							sfmt, r2);
					r1 = r2;
					r2 = i;
				}
				for (; i < 4 * N; i += 4) {
					doRecursion(sfmt, i, sfmt, i, sfmt, i + 4 * (POS1 - N),
							sfmt, r1, sfmt, r2);
					r1 = r2;
					r2 = i;
				}
				idx = 0;

				// ////////////// BLOCK MODE /////////////////
				if (even && longBuffer.remaining() >= 312) {

					for (; idx < N32;) {

						l = sfmt[idx++];
						r = sfmt[idx++];
						longBuffer.put((((long) l) << 32) + r);

						l = sfmt[idx++];
						r = sfmt[idx++];
						longBuffer.put((((long) l) << 32) + r);

						l = sfmt[idx++];
						r = sfmt[idx++];
						longBuffer.put((((long) l) << 32) + r);

						l = sfmt[idx++];
						r = sfmt[idx++];
						longBuffer.put((((long) l) << 32) + r);
					}
					longs += 312;
					continue;
				}
				// //////////////// BLOCK MODE /////////////////
			}

			l = sfmt[idx++];

			// ////////////////// GENERATE FUNCTION ///////////////////////////
			{

				if (idx >= N32) {

					int i = 0, r1 = 4 * (N - 2), r2 = 4 * (N - 1);
					for (; i < 4 * (N - POS1); i += 4) {
						doRecursion(sfmt, i, sfmt, i, sfmt, i + 4 * POS1, sfmt,
								r1, sfmt, r2);
						r1 = r2;
						r2 = i;
					}
					for (; i < 4 * N; i += 4) {
						doRecursion(sfmt, i, sfmt, i, sfmt, i + 4 * (POS1 - N),
								sfmt, r1, sfmt, r2);
						r1 = r2;
						r2 = i;
					}
					idx = 0;

					// ////////////// BLOCK MODE (ODD CASE) //////////////
					if (!even && longBuffer.remaining() >= 312) {

						{
							r = sfmt[idx++];
							longBuffer.put((((long) l) << 32) + r);
							longs++;
						}

						for (; idx < (N32 - 1);) {

							l = sfmt[idx++];
							r = sfmt[idx++];
							longBuffer.put((((long) l) << 32) + r);
						}

						longs += 311;
						continue;
					}
					// //////////////// BLOCK MODE /////////////////
				}
				r = sfmt[idx++];
			}

			longBuffer.put((((long) l) << 32) + (long) r);
			longs++;
		}

		return numLongs - longBuffer.remaining();
	}

	@Override
	public final int read(DoubleBuffer doubleBuffer) {

		final int numDoubles = doubleBuffer.remaining();

		int doubles = 0;

		final boolean even = (idx % 2) == 0;

		for (; doubles < numDoubles;) {

			if (shared && !isOpen()) // check interruption status
				return doubles; // interrupt

			int l;
			int r;

			// ///////////////// GENERATE FUNCTION /////////////////////
			{
				if (idx >= N32) {

					int i = 0, r1 = 4 * (N - 2), r2 = 4 * (N - 1);
					for (; i < 4 * (N - POS1); i += 4) {
						doRecursion(sfmt, i, sfmt, i, sfmt, i + 4 * POS1, sfmt,
								r1, sfmt, r2);
						r1 = r2;
						r2 = i;
					}
					for (; i < 4 * N; i += 4) {
						doRecursion(sfmt, i, sfmt, i, sfmt, i + 4 * (POS1 - N),
								sfmt, r1, sfmt, r2);
						r1 = r2;
						r2 = i;
					}
					idx = 0;

					// ////////////// BLOCK MODE /////////////////
					if (even && doubleBuffer.remaining() >= 312) {

						for (; idx < N32;) {

							l = sfmt[idx++];
							r = sfmt[idx++];
							doubleBuffer
									.put(((((long) (l >>> 6)) << 27) + (r >>> 5))
											/ (double) (1L << 53));

							l = sfmt[idx++];
							r = sfmt[idx++];
							doubleBuffer
									.put(((((long) (l >>> 6)) << 27) + (r >>> 5))
											/ (double) (1L << 53));

							l = sfmt[idx++];
							r = sfmt[idx++];
							doubleBuffer
									.put(((((long) (l >>> 6)) << 27) + (r >>> 5))
											/ (double) (1L << 53));

							l = sfmt[idx++];
							r = sfmt[idx++];
							doubleBuffer
									.put(((((long) (l >>> 6)) << 27) + (r >>> 5))
											/ (double) (1L << 53));
						}
						doubles += 312;
						continue;
					}
					// //////////////// BLOCK MODE /////////////////

				}
			}

			l = sfmt[idx++];

			{
				if (idx >= N32) {

					int i = 0, r1 = 4 * (N - 2), r2 = 4 * (N - 1);
					for (; i < 4 * (N - POS1); i += 4) {
						doRecursion(sfmt, i, sfmt, i, sfmt, i + 4 * POS1, sfmt,
								r1, sfmt, r2);
						r1 = r2;
						r2 = i;
					}
					for (; i < 4 * N; i += 4) {
						doRecursion(sfmt, i, sfmt, i, sfmt, i + 4 * (POS1 - N),
								sfmt, r1, sfmt, r2);
						r1 = r2;
						r2 = i;
					}
					idx = 0;

					// ////////////// BLOCK MODE (ODD CASE) //////////////
					if (!even && doubleBuffer.remaining() >= 312) {

						{
							r = sfmt[idx++];
							doubleBuffer
									.put(((((long) (l >>> 6)) << 27) + (r >>> 5))
											/ (double) (1L << 53));
							doubles++;
						}

						for (; idx < (N32 - 1);) {

							l = sfmt[idx++];
							r = sfmt[idx++];
							doubleBuffer
									.put(((((long) (l >>> 6)) << 27) + (r >>> 5))
											/ (double) (1L << 53));
						}
						doubles += 311;
						continue;
					}
					// //////////////// BLOCK MODE /////////////////
				}
				r = sfmt[idx++];
			}

			doubleBuffer.put(((((long) (l >>> 6)) << 27) + (r >>> 5))
					/ (double) (1L << 53));
			doubles++;
		}

		return numDoubles - doubleBuffer.remaining() /* should be zero */;
	}

	@Override
	public final int nextInt() {
		if (idx >= N32) {
			int i = 0, r1 = 4 * (N - 2), r2 = 4 * (N - 1);
			for (; i < 4 * (N - POS1); i += 4) {
				doRecursion(sfmt, i, sfmt, i, sfmt, i + 4 * POS1, sfmt, r1,
						sfmt, r2);
				r1 = r2;
				r2 = i;
			}
			for (; i < 4 * N; i += 4) {
				doRecursion(sfmt, i, sfmt, i, sfmt, i + 4 * (POS1 - N), sfmt,
						r1, sfmt, r2);
				r1 = r2;
				r2 = i;
			}
			idx = 0;
		}
		return sfmt[idx++];
	}

	@Override
	public final float nextFloat() {
		if (idx >= N32) {
			int i = 0, r1 = 4 * (N - 2), r2 = 4 * (N - 1);
			for (; i < 4 * (N - POS1); i += 4) {
				doRecursion(sfmt, i, sfmt, i, sfmt, i + 4 * POS1, sfmt, r1,
						sfmt, r2);
				r1 = r2;
				r2 = i;
			}
			for (; i < 4 * N; i += 4) {
				doRecursion(sfmt, i, sfmt, i, sfmt, i + 4 * (POS1 - N), sfmt,
						r1, sfmt, r2);
				r1 = r2;
				r2 = i;
			}
			idx = 0;
		}

		return (sfmt[idx++] >>> 8) / ((float) (1 << 24));
	}

	@Override
	public final long nextLong() {
		int l;
		int r;

		// ///////////////// GENERATE FUNCTION /////////////////////
		{
			if (idx >= N32) {

				int i = 0, r1 = 4 * (N - 2), r2 = 4 * (N - 1);
				for (; i < 4 * (N - POS1); i += 4) {
					doRecursion(sfmt, i, sfmt, i, sfmt, i + 4 * POS1, sfmt, r1,
							sfmt, r2);
					r1 = r2;
					r2 = i;
				}
				for (; i < 4 * N; i += 4) {
					doRecursion(sfmt, i, sfmt, i, sfmt, i + 4 * (POS1 - N),
							sfmt, r1, sfmt, r2);
					r1 = r2;
					r2 = i;
				}
				idx = 0;
			}
			l = sfmt[idx++];
		}
		// ////////////////// GENERATE FUNCTION ///////////////////////////
		{
			{
				if (idx >= N32) {

					int i = 0, r1 = 4 * (N - 2), r2 = 4 * (N - 1);
					for (; i < 4 * (N - POS1); i += 4) {
						doRecursion(sfmt, i, sfmt, i, sfmt, i + 4 * POS1, sfmt,
								r1, sfmt, r2);
						r1 = r2;
						r2 = i;
					}
					for (; i < 4 * N; i += 4) {
						doRecursion(sfmt, i, sfmt, i, sfmt, i + 4 * (POS1 - N),
								sfmt, r1, sfmt, r2);
						r1 = r2;
						r2 = i;
					}
					idx = 0;
				}
				r = sfmt[idx++];
			}
		}
		return ((((long) l) << 32) + r);
	}

	@Override
	public final double nextDouble() {
		int l;
		int r;

		// ///////////////// GENERATE FUNCTION /////////////////////
		{
			if (idx >= N32) {

				int i = 0, r1 = 4 * (N - 2), r2 = 4 * (N - 1);
				for (; i < 4 * (N - POS1); i += 4) {
					doRecursion(sfmt, i, sfmt, i, sfmt, i + 4 * POS1, sfmt, r1,
							sfmt, r2);
					r1 = r2;
					r2 = i;
				}
				for (; i < 4 * N; i += 4) {
					doRecursion(sfmt, i, sfmt, i, sfmt, i + 4 * (POS1 - N),
							sfmt, r1, sfmt, r2);
					r1 = r2;
					r2 = i;
				}
				idx = 0;
			}
			l = sfmt[idx++];
		}
		// ////////////////// GENERATE FUNCTION ///////////////////////////
		{
			{
				if (idx >= N32) {

					int i = 0, r1 = 4 * (N - 2), r2 = 4 * (N - 1);
					for (; i < 4 * (N - POS1); i += 4) {
						doRecursion(sfmt, i, sfmt, i, sfmt, i + 4 * POS1, sfmt,
								r1, sfmt, r2);
						r1 = r2;
						r2 = i;
					}
					for (; i < 4 * N; i += 4) {
						doRecursion(sfmt, i, sfmt, i, sfmt, i + 4 * (POS1 - N),
								sfmt, r1, sfmt, r2);
						r1 = r2;
						r2 = i;
					}
					idx = 0;
				}
				r = sfmt[idx++];
			}
		}
		return (((((long) (l >>> 6)) << 27) + (r >>> 5)) / (double) (1L << 53));
	}

	/**
	 * Applies the recursion formula.
	 * 
	 * @param r
	 *            output array.
	 * @param rI
	 *            index in <code>r</code>.
	 * @param a
	 *            state array.
	 * @param aI
	 *            index in <code>a</code>.
	 * @param b
	 *            state array.
	 * @param bI
	 *            index in <code>b</code>.
	 * @param c
	 *            state array.
	 * @param cI
	 *            index in <code>c</code>.
	 * @param d
	 *            state array.
	 * @param dI
	 *            index in <code>d</code>.
	 */
	private static final void doRecursion(int[] r, int rI, int[] a, int aI,
			int[] b, int bI, int[] c, int cI, int[] d, int dI) {
		// 128-bit shift: x = a << SL2 * 8:
		final int lShift = SL2 * 8;
		int a0 = a[aI], a1 = a[aI + 1], a2 = a[aI + 2], a3 = a[aI + 3];
		// for SL2 <= 3, this is more concise, but possibly not as fast (haven't
		// timed it):
		// int x0 = a0 << lShift,
		// x1 = (a1 << lShift) | (a0 >>> (32 - lShift)),
		// x2 = (a2 << lShift) | (a1 >>> (32 - lShift)),
		// x3 = (a3 << lShift) | (a2 >>> (32 - lShift));
		long hi = ((long) a3 << 32) | (a2 & (-1L >>> 32)), lo = ((long) a1 << 32)
				| (a0 & (-1L >>> 32)), outLo = lo << lShift, outHi = (hi << lShift)
				| (lo >>> (64 - lShift));

		int x0 = (int) outLo, x1 = (int) (outLo >>> 32), x2 = (int) outHi, x3 = (int) (outHi >>> 32);
		// 128-bit shift: y = c >>> SR2 * 8:

		final int rShift = SR2 * 8;
		hi = ((long) c[cI + 3] << 32) | (c[cI + 2] & (-1L >>> 32));
		lo = ((long) c[cI + 1] << 32) | (c[cI] & (-1L >>> 32));
		outHi = hi >>> rShift;
		outLo = (lo >>> rShift) | (hi << (64 - rShift));
		int y0 = (int) outLo, y1 = (int) (outLo >>> 32), y2 = (int) outHi, y3 = (int) (outHi >>> 32);

		// rest of forumula:
		r[rI] = a0 ^ x0 ^ ((b[bI] >>> SR1) & MSK1) ^ y0 ^ (d[dI] << SL1);
		r[rI + 1] = a1 ^ x1 ^ ((b[bI + 1] >>> SR1) & MSK2) ^ y1
				^ (d[dI + 1] << SL1);
		r[rI + 2] = a2 ^ x2 ^ ((b[bI + 2] >>> SR1) & MSK3) ^ y2
				^ (d[dI + 2] << SL1);
		r[rI + 3] = a3 ^ x3 ^ ((b[bI + 3] >>> SR1) & MSK4) ^ y3
				^ (d[dI + 3] << SL1);
	}

	/**
	 * Used by {@link #initByArray}.
	 * 
	 * @param x
	 *            32-bit integer.
	 * @return 32-bit integer.
	 */
	private static final int func1(int x) {
		return (x ^ (x >>> 27)) * 1664525;
	}

	/**
	 * Used by {@link #initByArray}.
	 * 
	 * @param x
	 *            32-bit integer.
	 * @return 32-bit integer.
	 */
	private static final int func2(int x) {
		return (x ^ (x >>> 27)) * 1566083941;
	}

	/**
	 * Certifies the period of 2<sup>{@link #MEXP}</sup>.
	 */
	private final void periodCertification() {
		int inner = 0;
		for (int i = 0; i < 4; i++)
			inner ^= sfmt[i] & parity[i];
		for (int i = 16; i > 0; i >>= 1)
			inner ^= inner >> i;
		if ((inner & 1) != 0) // check OK
			return;
		for (int i = 0; i < 4; i++) {
			int work = 1;
			for (int j = 0; j < 32; j++) {
				if ((work & parity[i]) != 0) {
					sfmt[i] ^= work;
					return;
				}
				work <<= 1;
			}
		}
	}

	// /**
	// * Fills a user-specified array with pseudorandom integers.
	// *
	// * @param array
	// * 128-bit array to be filled with pseudorandom numbers.
	// * @param size
	// * number of elements of <code>array</code> to fill.
	// * @throws IllegalArgumentException
	// * if <code>size</code> is greater than the length of
	// * <code>array</code>, or if <code>size</code> is less than
	// * {@link #N32}, or is not a multiple of 4.
	// */
	// void genRandArray(int[] array, int size) {
	// if (size < N32)
	// throw new IllegalArgumentException("Size must be at least " + N32
	// + ", but is " + size);
	// if (size % 4 != 0)
	// throw new IllegalArgumentException("Size must be a multiple of 4: "
	// + size);
	//
	// size = array.length;
	//
	// int i = 0, j = 0, r1I = 4 * (N - 2), r2I = 4 * (N - 1);
	// int[] r1 = sfmt, r2 = sfmt;
	// for (; i < 4 * (N - POS1); i += 4) {
	// doRecursion(array, i, sfmt, i, sfmt, i + 4 * POS1, r1, r1I, r2, r2I);
	// r1 = r2;
	// r1I = r2I;
	// r2 = array;
	// r2I = i;
	// }
	// for (; i < 4 * N; i += 4) {
	// doRecursion(array, i, sfmt, i, array, i + 4 * (POS1 - N), r1, r1I,
	// r2, r2I);
	// assert r1 == r2;
	// r1I = r2I;
	// assert r2 == array;
	// r2I = i;
	// }
	// for (; i < size - 4 * N; i += 4) {
	// doRecursion(array, i, array, i - 4 * N, array, i + 4 * (POS1 - N),
	// r1, r1I, r2, r2I);
	// assert r1 == r2;
	// r1I = r2I;
	// assert r2 == array;
	// r2I = i;
	// }
	// for (; j < 4 * 2 * N - size; j++)
	// sfmt[j] = array[j + size - 4 * N];
	// for (; i < size; i += 4, j += 4) {
	// doRecursion(array, i, array, i - 4 * N, array, i + 4 * (POS1 - N),
	// r1, r1I, r2, r2I);
	// assert r1 == r2;
	// r1I = r2I;
	// assert r2 == array;
	// r2I = i;
	// sfmt[j] = array[i];
	// sfmt[j + 1] = array[i + 1];
	// sfmt[j + 2] = array[i + 2];
	// sfmt[j + 3] = array[i + 3];
	// }
	// }
	//
	// /**
	// * Fills the given array with pseudorandom 32-bit integers. Equivalent to
	// * {@link #fillArray(int[],int)} applied to
	// * <code>(array,array.length)</code>.
	// *
	// * @param array
	// * array to fill.
	// */
	// void fillArray(int[] array) {
	// genRandArray(array, array.length);
	// }
	//
	// /**
	// * Fills the given array with the specified number of pseudorandom 32-bit
	// * integers. The specified number of elements must be a multiple of four.
	// *
	// * @param array
	// * array to fill.
	// * @param elems
	// * the number of elements of <code>array</code> (starting at
	// * index zero) to fill; subsequent elements are not modified.
	// * @throws IllegalArgumentException
	// * if <code>elems</code> is greater than the length of
	// * <code>array</code>, or is less than {@link #N32}, or is not a
	// * multiple of 4.
	// */
	// void fillArray(int[] array, int elems) {
	// genRandArray(array, elems);
	// idx = N32;
	// }

	public int idx() {
		return idx;
	};

	@Override
	public int[] sfmt() {
		return sfmt;
	}

	@Override
	public final String toString() {
		return PRNG.SFMT.name();
	}

	@Override
	public final Pseudorandomness copy() {
		SFMT sfmt19937 = new SFMT();

		sfmt19937.reseed((ByteBuffer) this.mark.clear());
		sfmt19937.idx = this.idx;
		System.arraycopy(this.sfmt, 0, sfmt19937.sfmt, 0, this.sfmt.length);

		return sfmt19937;
	}

	@Override
	public final int hashCode() {
		if (!isOpen())
			return System.identityHashCode(this);

		int hash = 51;
		hash = 37 * hash + Arrays.hashCode(sfmt);
		hash = 37 * hash + MEXP;
		return 31 * hash + idx;
	}

	@Override
	public final boolean equals(Object obj) {

		if (obj == null)
			return false;

		if (!this.isOpen())
			return false;

		if (obj == this)
			return true;

		if (!(obj instanceof Pseudorandomness))
			return false;

		if (!((Pseudorandomness) obj).isOpen())
			return false;

		if (!(obj instanceof Engine.SFMT))
			return false;

		Engine.SFMT other = (Engine.SFMT) obj;
		if (this.idx() != other.idx())
			return false;

		if (!Arrays.equals(this.sfmt(), other.sfmt()))
			return false;

		return true;
	}

	@Override
	public final int minlen() {
		return INT_SIZE_BYTES;
	}

	@Override
	public final int period() {
		return MEXP;
	}

	/**
	 * Shared wrapper around SFMT
	 * 
	 * @author Anton Kabysh
	 * 
	 */
	final class Shared extends Pseudorandomness implements Engine.SFMT {
		/**
		 * 
		 */
		private static final long serialVersionUID = 1L;

		private final AtomicInteger idx = new AtomicInteger(0);
		private final ReentrantLock lock = new ReentrantLock();
		private final SFMT _this = SFMT.this;

		public Shared() {
			idx.set(_this.idx);
			assert shared == true;
		}

		@Override
		protected final int seedlen() {
			return SFMT.this.seedlen();
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

				idx.set(_this.idx);

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
				idx.set(_this.idx);

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

		@Override
		public final int read(ByteBuffer buffer) {
			if (!isOpen())
				throw new NonReadableChannelException();

			final int numBytes = buffer.remaining();

			try {
				lock.lock();
				_this.idx = acquireCounter();

				nextInt = nextLong = true; // clear intermediate state
				_this.read(buffer);

				releaseCounter(_this.idx); // restore counter to global state
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
				_this.idx = acquireCounter();
				nextInt = nextLong = true; // clear intermediate state

				_this.read(intBuffer);

				releaseCounter(_this.idx); // restore counter to global state
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

				_this.idx = acquireCounter();
				nextInt = nextLong = true; // clear intermediate state

				_this.read(floatBuffer);

				releaseCounter(_this.idx); // restore counter to global state
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
				_this.idx = acquireCounter();
				nextInt = nextLong = true; // clear intermediate state

				_this.read(longBuffer);

				releaseCounter(_this.idx); // restore counter to global state
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
				_this.idx = acquireCounter();
				nextInt = nextLong = true; // clear intermediate state

				_this.read(doubleBuffer);

				releaseCounter(_this.idx); // restore counter to global state
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
			return _this.toString();
		}

		@Override
		public final Pseudorandomness copy() {

			if (!isOpen())
				throw new NonReadableChannelException();

			try {
				lock.lock();

				SFMT mt = (SFMT) _this.copy();

				SFMT.Shared sharedCopy = mt.new Shared();

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

				// assert mtI == _this.idx;

				int next = mtI + 1;

				if (mtI < 0) // can't generate, buffer is not ready
					continue;

				if (mtI >= N32) {

					if (!idx.compareAndSet(mtI, -1)) // try acquire lock
						continue; // counter state is changed

					int i = 0, r1 = 4 * (N - 2), r2 = 4 * (N - 1);
					for (; i < 4 * (N - POS1); i += 4) {
						doRecursion(sfmt, i, sfmt, i, sfmt, i + 4 * POS1, sfmt,
								r1, sfmt, r2);
						r1 = r2;
						r2 = i;
					}
					for (; i < 4 * N; i += 4) {
						doRecursion(sfmt, i, sfmt, i, sfmt, i + 4 * (POS1 - N),
								sfmt, r1, sfmt, r2);
						r1 = r2;
						r2 = i;
					}
					mtI = 0;

					y = sfmt[mtI];
					idx.set(1); // reset state from -1

					break;
				}

				y = sfmt[mtI];

				if (idx.compareAndSet(mtI, next)) {
					break;
				}
			}

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

				if (mtI >= N32) {

					if (!idx.compareAndSet(mtI, -1)) // try acquire lock
						continue; // counter state is changed

					int i = 0, r1 = 4 * (N - 2), r2 = 4 * (N - 1);
					for (; i < 4 * (N - POS1); i += 4) {
						doRecursion(sfmt, i, sfmt, i, sfmt, i + 4 * POS1, sfmt,
								r1, sfmt, r2);
						r1 = r2;
						r2 = i;
					}
					for (; i < 4 * N; i += 4) {
						doRecursion(sfmt, i, sfmt, i, sfmt, i + 4 * (POS1 - N),
								sfmt, r1, sfmt, r2);
						r1 = r2;
						r2 = i;
					}
					mtI = 0;

					y = sfmt[mtI];
					idx.set(1); // reset state from -1

					break;
				}

				y = sfmt[mtI];

				if (idx.compareAndSet(mtI, next)) {
					break;
				}
			}

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

				if (mtI == (N32 - 1)) { // only one 32 word in buffer

					if (!idx.compareAndSet(mtI, -1)) // try acquire lock
						continue; // counter state is changed

					l = sfmt[mtI];

					// /////////////// GENERATE FUNCTION ////////////////////
					{
						int i = 0, r1 = 4 * (N - 2), r2 = 4 * (N - 1);
						for (; i < 4 * (N - POS1); i += 4) {
							doRecursion(sfmt, i, sfmt, i, sfmt, i + 4 * POS1,
									sfmt, r1, sfmt, r2);
							r1 = r2;
							r2 = i;
						}
						for (; i < 4 * N; i += 4) {
							doRecursion(sfmt, i, sfmt, i, sfmt, i + 4
									* (POS1 - N), sfmt, r1, sfmt, r2);
							r1 = r2;
							r2 = i;
						}
						mtI = 0;
					}

					r = sfmt[0];
					idx.set(1); // reset from -1 state
					break;
				}

				if (mtI >= N32) {

					if (!idx.compareAndSet(mtI, -1)) // try acquire lock
						continue; // counter state is changed

					int i = 0, r1 = 4 * (N - 2), r2 = 4 * (N - 1);
					for (; i < 4 * (N - POS1); i += 4) {
						doRecursion(sfmt, i, sfmt, i, sfmt, i + 4 * POS1, sfmt,
								r1, sfmt, r2);
						r1 = r2;
						r2 = i;
					}
					for (; i < 4 * N; i += 4) {
						doRecursion(sfmt, i, sfmt, i, sfmt, i + 4 * (POS1 - N),
								sfmt, r1, sfmt, r2);
						r1 = r2;
						r2 = i;
					}
					mtI = 0;

					l = sfmt[0];
					r = sfmt[1];

					idx.set(2); // reset state from -1
					break;
				}

				// normal generation
				l = sfmt[mtI];
				r = sfmt[mtI + 1];

				if (idx.compareAndSet(mtI, next)) {
					break;
				}
			}

			return (((long) l) << 32) + (long) r;
		}

		@Override
		public double nextDouble() {
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

				if (mtI == (N32 - 1)) { // only one 32 word in buffer

					if (!idx.compareAndSet(mtI, -1)) // try acquire lock
						continue; // counter state is changed

					l = sfmt[mtI];

					// /////////////// GENERATE FUNCTION ////////////////////
					{
						int i = 0, r1 = 4 * (N - 2), r2 = 4 * (N - 1);
						for (; i < 4 * (N - POS1); i += 4) {
							doRecursion(sfmt, i, sfmt, i, sfmt, i + 4 * POS1,
									sfmt, r1, sfmt, r2);
							r1 = r2;
							r2 = i;
						}
						for (; i < 4 * N; i += 4) {
							doRecursion(sfmt, i, sfmt, i, sfmt, i + 4
									* (POS1 - N), sfmt, r1, sfmt, r2);
							r1 = r2;
							r2 = i;
						}
						mtI = 0;
					}

					r = sfmt[0];
					idx.set(1); // reset from -1 state
					break;
				}

				if (mtI >= N32) {

					if (!idx.compareAndSet(mtI, -1)) // try acquire lock
						continue; // counter state is changed

					int i = 0, r1 = 4 * (N - 2), r2 = 4 * (N - 1);
					for (; i < 4 * (N - POS1); i += 4) {
						doRecursion(sfmt, i, sfmt, i, sfmt, i + 4 * POS1, sfmt,
								r1, sfmt, r2);
						r1 = r2;
						r2 = i;
					}
					for (; i < 4 * N; i += 4) {
						doRecursion(sfmt, i, sfmt, i, sfmt, i + 4 * (POS1 - N),
								sfmt, r1, sfmt, r2);
						r1 = r2;
						r2 = i;
					}
					mtI = 0;

					l = sfmt[0];
					r = sfmt[1];

					idx.set(2); // reset state from -1
					break;
				}

				// normal generation
				l = sfmt[mtI];
				r = sfmt[mtI + 1];

				if (idx.compareAndSet(mtI, next)) {
					break;
				}
			}

			return ((((long) (l >>> 6)) << 27) + (r >>> 5))
					/ (double) (1L << 53);
		}

		@Override
		public int idx() {
			return _this.idx();
		}

		@Override
		public int[] sfmt() {
			return _this.sfmt();
		}
	}
}
