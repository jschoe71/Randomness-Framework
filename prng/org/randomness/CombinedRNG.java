package org.randomness;

import java.nio.ByteBuffer;
import java.nio.DoubleBuffer;
import java.nio.FloatBuffer;
import java.nio.IntBuffer;
import java.nio.LongBuffer;
import java.util.Random;

/**
 * It is a <b>combined 64-bit generator</b>: {@linkplain PRNG#XOR_SHIFT
 * XOR-Shift} generators are combined with an {@linkplain PRNG#LCG LCG} and a
 * <i>multiply with carry</i> generator producing . Without going into all the
 * details here, notice the two blocks of three shifts each, which are the
 * XORShifts; the first line which is the LCG, similar to the standard
 * {@link Random}, and the line between the two XORShifts, which is a
 * Multiply-With-Carry generator. Purposed by authors of <a href=
 * "http://www.amazon.com/gp/product/0521880688?ie=UTF8&amp;tag=javamex-20&amp;linkCode=as2&amp;camp=1789&amp;creative=9325&amp;creativeASIN=0521880688"
 * >Numerical Recipes: The Art of Scientific Computing</a> and provide a good
 * compromise between quality and speed.
 * <p>
 * This generator is useful in cases where you need fast, good-quality
 * randomness but don't need cryptographic randomness, as provided by the <a
 * href= "http://www.javamex.com/tutorials/random_numbers/securerandom.shtml"
 * >Java SecureRandom</a> class. The code above is not much slower than
 * <tt>java.util.Random</tt> and provides much better quality randomness and a
 * much larger period. It is about 20 times faster than <tt>SecureRandom</tt>.
 * Typical candidates for using this generator would be <b>games and
 * simulations</b> (except games where money depends on the random number
 * generator, such as in gambling applications).
 * 
 * </p>
 * 
 * @author Neil Coffey (java port)
 * @author <a href="mailto:anton.kabysh@gmail.com">Anton Kabysh</a> (randomness
 *         adaptation)
 */
final class CombinedRNG extends PseudorandomnessEngine {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	private long u;
	private long v = 4101842887655102017L;
	private long w = 1;

	public CombinedRNG() {
		this.reset();
	}

	@Override
	protected final void instantiate(ByteBuffer seed) {

		// defaults
		v = 4101842887655102017L;
		w = 1;

		u = seed.getLong() ^ v;

		generate64();
		v = u;
		generate64();
		w = v;
		generate64();
	}

	private long generate64() {
		u = u * 2862933555777941757L + 7046029254386353087L;
		v ^= v >>> 17;
		v ^= v << 31;
		v ^= v >>> 8;
		w = 4294957665L * (w & 0xffffffff) + (w >>> 32);
		long x = u ^ (u << 21);
		x ^= x >>> 35;
		x ^= x << 4;
		return (x + v) ^ w;
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
			u = u * 2862933555777941757L + 7046029254386353087L;
			v ^= v >>> 17;
			v ^= v << 31;
			v ^= v >>> 8;
			w = 4294957665L * (w & 0xffffffff) + (w >>> 32);
			long x = u ^ (u << 21);
			x ^= x >>> 35;
			x ^= x << 4;
			// ///////////////// GENERATE FUNCTION /////////////////////

			buffer.putLong((x + v) ^ w);
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
	public final int read(IntBuffer intBuffer) {
		final int numInts = intBuffer.remaining();

		int longs = 0;
		final int numLongs = numInts / (LONG_SIZE_BYTES / INT_SIZE_BYTES);

		for (; longs < numLongs;) {

			if (!isOpen()) // check interruption status
				return longs * (LONG_SIZE_BYTES / INT_SIZE_BYTES); // interrupt

			// ///////////////// GENERATE FUNCTION /////////////////////
			u = u * 2862933555777941757L + 7046029254386353087L;
			v ^= v >>> 17;
			v ^= v << 31;
			v ^= v >>> 8;
			w = 4294957665L * (w & 0xffffffff) + (w >>> 32);
			long x = u ^ (u << 21);
			x ^= x >>> 35;
			x ^= x << 4;
			// ///////////////// GENERATE FUNCTION /////////////////////
			x = (x + v) ^ w;

			intBuffer.put((int) (x >>> Integer.SIZE));
			intBuffer.put((int) x);
			longs++;
		}

		// if num is not odd, add last one
		for (; intBuffer.hasRemaining();) {

			intBuffer.put(nextInt());
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
				return longs * (LONG_SIZE_BYTES / INT_SIZE_BYTES); // interrupt

			// ///////////////// GENERATE FUNCTION /////////////////////
			u = u * 2862933555777941757L + 7046029254386353087L;
			v ^= v >>> 17;
			v ^= v << 31;
			v ^= v >>> 8;
			w = 4294957665L * (w & 0xffffffff) + (w >>> 32);
			long x = u ^ (u << 21);
			x ^= x >>> 35;
			x ^= x << 4;
			// ///////////////// GENERATE FUNCTION /////////////////////
			x = (x + v) ^ w;

			floatBuffer.put((((int) (x >>> Integer.SIZE)) >>> 8)
					/ ((float) (1 << 24)));
			floatBuffer.put((((int) x) >>> 8) / ((float) (1 << 24)));
			longs++;
		}

		// if num is not odd, add last one
		for (; floatBuffer.hasRemaining();) {
			int x = nextInt();
			floatBuffer.put((((int) x) >>> 8) / ((float) (1 << 24)));
		}

		return numFloats - floatBuffer.remaining();
	}

	@Override
	public final int read(LongBuffer longBuffer) {
		final int numLongs = longBuffer.remaining();

		for (int longs = 0; longs < numLongs;) {

			if (!isOpen()) // check interruption status
				return longs; // interrupt

			// ///////////////// GENERATE FUNCTION /////////////////////
			u = u * 2862933555777941757L + 7046029254386353087L;
			v ^= v >>> 17;
			v ^= v << 31;
			v ^= v >>> 8;
			w = 4294957665L * (w & 0xffffffff) + (w >>> 32);
			long x = u ^ (u << 21);
			x ^= x >>> 35;
			x ^= x << 4;
			// ///////////////// GENERATE FUNCTION /////////////////////

			longBuffer.put((x + v) ^ w);
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
			u = u * 2862933555777941757L + 7046029254386353087L;
			v ^= v >>> 17;
			v ^= v << 31;
			v ^= v >>> 8;
			w = 4294957665L * (w & 0xffffffff) + (w >>> 32);
			long x = u ^ (u << 21);
			x ^= x >>> 35;
			x ^= x << 4;
			// ///////////////// GENERATE FUNCTION /////////////////////

			doubleBuffer.put((((x + v) ^ w) >>> 11) / (double) (1L << 53));
			doubles++;

		}

		return numDoubles - doubleBuffer.remaining() /* should be zero */;
	}

	public final long nextLong() {
		u = u * 2862933555777941757L + 7046029254386353087L;
		v ^= v >>> 17;
		v ^= v << 31;
		v ^= v >>> 8;
		w = 4294957665L * (w & 0xffffffff) + (w >>> 32);
		long x = u ^ (u << 21);
		x ^= x >>> 35;
		x ^= x << 4;
		return (x + v) ^ w;
	}

	@Override
	public double nextDouble() {
		u = u * 2862933555777941757L + 7046029254386353087L;
		v ^= v >>> 17;
		v ^= v << 31;
		v ^= v >>> 8;
		w = 4294957665L * (w & 0xffffffff) + (w >>> 32);
		long x = u ^ (u << 21);
		x ^= x >>> 35;
		x ^= x << 4;
		return (((x + v) ^ w) >>> 11) / (double) (1L << 53);

	}

	public final int nextInt() {
		u = u * 2862933555777941757L + 7046029254386353087L;
		v ^= v >>> 17;
		v ^= v << 31;
		v ^= v >>> 8;
		w = 4294957665L * (w & 0xffffffff) + (w >>> 32);
		long x = u ^ (u << 21);
		x ^= x >>> 35;
		x ^= x << 4;
		x = (x + v) ^ w;
		return (int) (x >>> 32);
	}

	@Override
	public final float nextFloat() {
		u = u * 2862933555777941757L + 7046029254386353087L;
		v ^= v >>> 17;
		v ^= v << 31;
		v ^= v >>> 8;
		w = 4294957665L * (w & 0xffffffff) + (w >>> 32);
		long x = u ^ (u << 21);
		x ^= x >>> 35;
		x ^= x << 4;
		x = (x + v) ^ w;
		return (((int) (x >>> Integer.SIZE)) >>> 8) / ((float) (1 << 24));
	}

	@Override
	public final String toString() {
		return PRNG.COMBINED.name();
	}

	@Override
	public final int hashCode() {
		if (!isOpen())
			return System.identityHashCode(this);

		int hashCode = 7;
		hashCode = 31 * hashCode + (int) (w ^ (w >>> 32));
		hashCode = 31 * hashCode + (int) (u ^ (u >>> 32));
		return 31 * hashCode + (int) (v ^ (v >>> 32));
	}

	@Override
	public final boolean equals(Object obj) {

		if (obj == null)
			return false;

		if (!this.isOpen())
			return false;

		if (obj == this)
			return true;

		if (!(obj instanceof CombinedRNG))
			return false;

		CombinedRNG that = (CombinedRNG) obj;

		if (!that.isOpen())
			return false;

		return (this.w == that.w) && (this.u == that.u) && (this.v == that.v);
	}

	@Override
	public final CombinedRNG copy() {
		CombinedRNG copy = new CombinedRNG();
		copy.reseed((ByteBuffer) this.mark.clear());
		copy.v = this.v;
		copy.u = this.u;
		copy.w = this.w;

		return copy;
	}

	@Override
	public final int minlen() {
		return LONG_SIZE_BYTES;
	}
}
