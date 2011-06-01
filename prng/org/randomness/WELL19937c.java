package org.randomness;

import java.nio.ByteBuffer;
import java.nio.DoubleBuffer;
import java.nio.FloatBuffer;
import java.nio.IntBuffer;
import java.nio.LongBuffer;
import java.util.Arrays;

final class WELL19937c extends WELLBase {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	/** Number of bits in the pool. */
	private static final int K = 19937;

	/** First parameter of the algorithm. */
	private static final int M1 = 70;

	/** Second parameter of the algorithm. */
	private static final int M2 = 179;

	/** Third parameter of the algorithm. */
	private static final int M3 = 449;

	/**
	 * Creates a new random number generator.
	 * <p>
	 * The instance is initialized using the current time as the seed.
	 * </p>
	 */
	WELL19937c() {
		super(K, M1, M2, M3);
		this.reset();
	}

	private int generate32() {
		final int indexRm1 = iRm1[index];
		final int indexRm2 = iRm2[index];

		final int v0 = v[index];
		final int vM1 = v[i1[index]];
		final int vM2 = v[i2[index]];
		final int vM3 = v[i3[index]];

		final int z0 = (0x80000000 & v[indexRm1]) ^ (0x7FFFFFFF & v[indexRm2]);
		final int z1 = (v0 ^ (v0 << 25)) ^ (vM1 ^ (vM1 >>> 27));
		final int z2 = (vM2 >>> 9) ^ (vM3 ^ (vM3 >>> 1));
		final int z3 = z1 ^ z2;
		int z4 = z0 ^ (z1 ^ (z1 << 9)) ^ (z2 ^ (z2 << 21)) ^ (z3 ^ (z3 >>> 21));

		v[index] = z3;
		v[indexRm1] = z4;
		v[indexRm2] &= 0x80000000;
		index = indexRm1;

		// add Matsumoto-Kurita tempering
		// to get a maximally-equidistributed generator
		z4 = z4 ^ ((z4 << 7) & 0xe46e1700);
		z4 = z4 ^ ((z4 << 15) & 0x9b868000);

		return z4;
	}

	@Override
	public final int read(ByteBuffer buffer) {
		final int numBytes = buffer.remaining();

		int bytes = 0;

		for (; (numBytes - bytes) >= INT_SIZE_BYTES;) {

			if (shared && !isOpen()) // check interruption status
				return bytes; // interrupt

			// ///////////////// GENERATE FUNCTION /////////////////////
			final int indexRm1 = iRm1[index];
			final int indexRm2 = iRm2[index];

			final int v0 = v[index];
			final int vM1 = v[i1[index]];
			final int vM2 = v[i2[index]];
			final int vM3 = v[i3[index]];

			final int z0 = (0x80000000 & v[indexRm1])
					^ (0x7FFFFFFF & v[indexRm2]);
			final int z1 = (v0 ^ (v0 << 25)) ^ (vM1 ^ (vM1 >>> 27));
			final int z2 = (vM2 >>> 9) ^ (vM3 ^ (vM3 >>> 1));
			final int z3 = z1 ^ z2;
			int z4 = z0 ^ (z1 ^ (z1 << 9)) ^ (z2 ^ (z2 << 21))
					^ (z3 ^ (z3 >>> 21));

			v[index] = z3;
			v[indexRm1] = z4;
			v[indexRm2] &= 0x80000000;
			index = indexRm1;

			// add Matsumoto-Kurita tempering
			// to get a maximally-equidistributed generator
			z4 = z4 ^ ((z4 << 7) & 0xe46e1700);
			z4 = z4 ^ ((z4 << 15) & 0x9b868000);

			// ///////////////// GENERATE FUNCTION /////////////////////

			buffer.putInt(z4);
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
			final int indexRm1 = iRm1[index];
			final int indexRm2 = iRm2[index];

			final int v0 = v[index];
			final int vM1 = v[i1[index]];
			final int vM2 = v[i2[index]];
			final int vM3 = v[i3[index]];

			final int z0 = (0x80000000 & v[indexRm1])
					^ (0x7FFFFFFF & v[indexRm2]);
			final int z1 = (v0 ^ (v0 << 25)) ^ (vM1 ^ (vM1 >>> 27));
			final int z2 = (vM2 >>> 9) ^ (vM3 ^ (vM3 >>> 1));
			final int z3 = z1 ^ z2;
			int z4 = z0 ^ (z1 ^ (z1 << 9)) ^ (z2 ^ (z2 << 21))
					^ (z3 ^ (z3 >>> 21));

			v[index] = z3;
			v[indexRm1] = z4;
			v[indexRm2] &= 0x80000000;
			index = indexRm1;

			// add Matsumoto-Kurita tempering
			// to get a maximally-equidistributed generator
			z4 = z4 ^ ((z4 << 7) & 0xe46e1700);
			z4 = z4 ^ ((z4 << 15) & 0x9b868000);
			// ///////////////// GENERATE FUNCTION /////////////////////

			intBuffer.put(z4);
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
			final int indexRm1 = iRm1[index];
			final int indexRm2 = iRm2[index];

			final int v0 = v[index];
			final int vM1 = v[i1[index]];
			final int vM2 = v[i2[index]];
			final int vM3 = v[i3[index]];

			final int z0 = (0x80000000 & v[indexRm1])
					^ (0x7FFFFFFF & v[indexRm2]);
			final int z1 = (v0 ^ (v0 << 25)) ^ (vM1 ^ (vM1 >>> 27));
			final int z2 = (vM2 >>> 9) ^ (vM3 ^ (vM3 >>> 1));
			final int z3 = z1 ^ z2;
			int z4 = z0 ^ (z1 ^ (z1 << 9)) ^ (z2 ^ (z2 << 21))
					^ (z3 ^ (z3 >>> 21));

			v[index] = z3;
			v[indexRm1] = z4;
			v[indexRm2] &= 0x80000000;
			index = indexRm1;

			// add Matsumoto-Kurita tempering
			// to get a maximally-equidistributed generator
			z4 = z4 ^ ((z4 << 7) & 0xe46e1700);
			z4 = z4 ^ ((z4 << 15) & 0x9b868000);
			// ///////////////// GENERATE FUNCTION /////////////////////

			floatBuffer.put((z4 >>> 8) / ((float) (1 << 24)));
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
				final int indexRm1 = iRm1[index];
				final int indexRm2 = iRm2[index];

				final int v0 = v[index];
				final int vM1 = v[i1[index]];
				final int vM2 = v[i2[index]];
				final int vM3 = v[i3[index]];

				final int z0 = (0x80000000 & v[indexRm1])
						^ (0x7FFFFFFF & v[indexRm2]);
				final int z1 = (v0 ^ (v0 << 25)) ^ (vM1 ^ (vM1 >>> 27));
				final int z2 = (vM2 >>> 9) ^ (vM3 ^ (vM3 >>> 1));
				final int z3 = z1 ^ z2;
				int z4 = z0 ^ (z1 ^ (z1 << 9)) ^ (z2 ^ (z2 << 21))
						^ (z3 ^ (z3 >>> 21));

				v[index] = z3;
				v[indexRm1] = z4;
				v[indexRm2] &= 0x80000000;
				index = indexRm1;

				// add Matsumoto-Kurita tempering
				// to get a maximally-equidistributed generator
				z4 = z4 ^ ((z4 << 7) & 0xe46e1700);
				z4 = z4 ^ ((z4 << 15) & 0x9b868000);

				l = z4;
			}
			{
				final int indexRm1 = iRm1[index];
				final int indexRm2 = iRm2[index];

				final int v0 = v[index];
				final int vM1 = v[i1[index]];
				final int vM2 = v[i2[index]];
				final int vM3 = v[i3[index]];

				final int z0 = (0x80000000 & v[indexRm1])
						^ (0x7FFFFFFF & v[indexRm2]);
				final int z1 = (v0 ^ (v0 << 25)) ^ (vM1 ^ (vM1 >>> 27));
				final int z2 = (vM2 >>> 9) ^ (vM3 ^ (vM3 >>> 1));
				final int z3 = z1 ^ z2;
				int z4 = z0 ^ (z1 ^ (z1 << 9)) ^ (z2 ^ (z2 << 21))
						^ (z3 ^ (z3 >>> 21));

				v[index] = z3;
				v[indexRm1] = z4;
				v[indexRm2] &= 0x80000000;
				index = indexRm1;

				// add Matsumoto-Kurita tempering
				// to get a maximally-equidistributed generator
				z4 = z4 ^ ((z4 << 7) & 0xe46e1700);
				z4 = z4 ^ ((z4 << 15) & 0x9b868000);

				r = z4;
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

		for (; doubles < numDoubles;) {

			if (shared && !isOpen()) // check interruption status
				return doubles; // interrupt

			int l;
			int r;

			// ///////////////// GENERATE FUNCTION /////////////////////
			{
				final int indexRm1 = iRm1[index];
				final int indexRm2 = iRm2[index];

				final int v0 = v[index];
				final int vM1 = v[i1[index]];
				final int vM2 = v[i2[index]];
				final int vM3 = v[i3[index]];

				final int z0 = (0x80000000 & v[indexRm1])
						^ (0x7FFFFFFF & v[indexRm2]);
				final int z1 = (v0 ^ (v0 << 25)) ^ (vM1 ^ (vM1 >>> 27));
				final int z2 = (vM2 >>> 9) ^ (vM3 ^ (vM3 >>> 1));
				final int z3 = z1 ^ z2;
				int z4 = z0 ^ (z1 ^ (z1 << 9)) ^ (z2 ^ (z2 << 21))
						^ (z3 ^ (z3 >>> 21));

				v[index] = z3;
				v[indexRm1] = z4;
				v[indexRm2] &= 0x80000000;
				index = indexRm1;

				// add Matsumoto-Kurita tempering
				// to get a maximally-equidistributed generator
				z4 = z4 ^ ((z4 << 7) & 0xe46e1700);
				z4 = z4 ^ ((z4 << 15) & 0x9b868000);

				l = z4;
			}
			{
				final int indexRm1 = iRm1[index];
				final int indexRm2 = iRm2[index];

				final int v0 = v[index];
				final int vM1 = v[i1[index]];
				final int vM2 = v[i2[index]];
				final int vM3 = v[i3[index]];

				final int z0 = (0x80000000 & v[indexRm1])
						^ (0x7FFFFFFF & v[indexRm2]);
				final int z1 = (v0 ^ (v0 << 25)) ^ (vM1 ^ (vM1 >>> 27));
				final int z2 = (vM2 >>> 9) ^ (vM3 ^ (vM3 >>> 1));
				final int z3 = z1 ^ z2;
				int z4 = z0 ^ (z1 ^ (z1 << 9)) ^ (z2 ^ (z2 << 21))
						^ (z3 ^ (z3 >>> 21));

				v[index] = z3;
				v[indexRm1] = z4;
				v[indexRm2] &= 0x80000000;
				index = indexRm1;

				// add Matsumoto-Kurita tempering
				// to get a maximally-equidistributed generator
				z4 = z4 ^ ((z4 << 7) & 0xe46e1700);
				z4 = z4 ^ ((z4 << 15) & 0x9b868000);

				r = z4;
			}

			doubleBuffer.put(((((long) (l >>> 6)) << 27) + (r >>> 5))
					/ (double) (1L << 53));
			doubles++;
		}

		return numDoubles - doubleBuffer.remaining() /* should be zero */;
	}

	@Override
	public final int nextInt() {
		final int indexRm1 = iRm1[index];
		final int indexRm2 = iRm2[index];

		final int v0 = v[index];
		final int vM1 = v[i1[index]];
		final int vM2 = v[i2[index]];
		final int vM3 = v[i3[index]];

		final int z0 = (0x80000000 & v[indexRm1]) ^ (0x7FFFFFFF & v[indexRm2]);
		final int z1 = (v0 ^ (v0 << 25)) ^ (vM1 ^ (vM1 >>> 27));
		final int z2 = (vM2 >>> 9) ^ (vM3 ^ (vM3 >>> 1));
		final int z3 = z1 ^ z2;
		int z4 = z0 ^ (z1 ^ (z1 << 9)) ^ (z2 ^ (z2 << 21)) ^ (z3 ^ (z3 >>> 21));

		v[index] = z3;
		v[indexRm1] = z4;
		v[indexRm2] &= 0x80000000;
		index = indexRm1;

		// add Matsumoto-Kurita tempering
		// to get a maximally-equidistributed generator
		z4 = z4 ^ ((z4 << 7) & 0xe46e1700);
		z4 = z4 ^ ((z4 << 15) & 0x9b868000);

		return z4;
	}

	@Override
	public final float nextFloat() {
		// ///////////////// GENERATE FUNCTION /////////////////////
		final int indexRm1 = iRm1[index];
		final int indexRm2 = iRm2[index];

		final int v0 = v[index];
		final int vM1 = v[i1[index]];
		final int vM2 = v[i2[index]];
		final int vM3 = v[i3[index]];

		final int z0 = (0x80000000 & v[indexRm1]) ^ (0x7FFFFFFF & v[indexRm2]);
		final int z1 = (v0 ^ (v0 << 25)) ^ (vM1 ^ (vM1 >>> 27));
		final int z2 = (vM2 >>> 9) ^ (vM3 ^ (vM3 >>> 1));
		final int z3 = z1 ^ z2;
		int z4 = z0 ^ (z1 ^ (z1 << 9)) ^ (z2 ^ (z2 << 21)) ^ (z3 ^ (z3 >>> 21));

		v[index] = z3;
		v[indexRm1] = z4;
		v[indexRm2] &= 0x80000000;
		index = indexRm1;

		// add Matsumoto-Kurita tempering
		// to get a maximally-equidistributed generator
		z4 = z4 ^ ((z4 << 7) & 0xe46e1700);
		z4 = z4 ^ ((z4 << 15) & 0x9b868000);
		// ///////////////// GENERATE FUNCTION /////////////////////

		return (z4 >>> 8) / ((float) (1 << 24));
	}

	@Override
	public final long nextLong() {
		int l;
		int r;

		// ///////////////// GENERATE FUNCTION /////////////////////
		{
			final int indexRm1 = iRm1[index];
			final int indexRm2 = iRm2[index];

			final int v0 = v[index];
			final int vM1 = v[i1[index]];
			final int vM2 = v[i2[index]];
			final int vM3 = v[i3[index]];

			final int z0 = (0x80000000 & v[indexRm1])
					^ (0x7FFFFFFF & v[indexRm2]);
			final int z1 = (v0 ^ (v0 << 25)) ^ (vM1 ^ (vM1 >>> 27));
			final int z2 = (vM2 >>> 9) ^ (vM3 ^ (vM3 >>> 1));
			final int z3 = z1 ^ z2;
			int z4 = z0 ^ (z1 ^ (z1 << 9)) ^ (z2 ^ (z2 << 21))
					^ (z3 ^ (z3 >>> 21));

			v[index] = z3;
			v[indexRm1] = z4;
			v[indexRm2] &= 0x80000000;
			index = indexRm1;

			// add Matsumoto-Kurita tempering
			// to get a maximally-equidistributed generator
			z4 = z4 ^ ((z4 << 7) & 0xe46e1700);
			z4 = z4 ^ ((z4 << 15) & 0x9b868000);

			l = z4;
		}
		{
			final int indexRm1 = iRm1[index];
			final int indexRm2 = iRm2[index];

			final int v0 = v[index];
			final int vM1 = v[i1[index]];
			final int vM2 = v[i2[index]];
			final int vM3 = v[i3[index]];

			final int z0 = (0x80000000 & v[indexRm1])
					^ (0x7FFFFFFF & v[indexRm2]);
			final int z1 = (v0 ^ (v0 << 25)) ^ (vM1 ^ (vM1 >>> 27));
			final int z2 = (vM2 >>> 9) ^ (vM3 ^ (vM3 >>> 1));
			final int z3 = z1 ^ z2;
			int z4 = z0 ^ (z1 ^ (z1 << 9)) ^ (z2 ^ (z2 << 21))
					^ (z3 ^ (z3 >>> 21));

			v[index] = z3;
			v[indexRm1] = z4;
			v[indexRm2] &= 0x80000000;
			index = indexRm1;

			// add Matsumoto-Kurita tempering
			// to get a maximally-equidistributed generator
			z4 = z4 ^ ((z4 << 7) & 0xe46e1700);
			z4 = z4 ^ ((z4 << 15) & 0x9b868000);

			r = z4;
		}

		return (((long) l) << 32) + r;

	}

	@Override
	public final double nextDouble() {
		int l;
		int r;

		// ///////////////// GENERATE FUNCTION /////////////////////
		{
			final int indexRm1 = iRm1[index];
			final int indexRm2 = iRm2[index];

			final int v0 = v[index];
			final int vM1 = v[i1[index]];
			final int vM2 = v[i2[index]];
			final int vM3 = v[i3[index]];

			final int z0 = (0x80000000 & v[indexRm1])
					^ (0x7FFFFFFF & v[indexRm2]);
			final int z1 = (v0 ^ (v0 << 25)) ^ (vM1 ^ (vM1 >>> 27));
			final int z2 = (vM2 >>> 9) ^ (vM3 ^ (vM3 >>> 1));
			final int z3 = z1 ^ z2;
			int z4 = z0 ^ (z1 ^ (z1 << 9)) ^ (z2 ^ (z2 << 21))
					^ (z3 ^ (z3 >>> 21));

			v[index] = z3;
			v[indexRm1] = z4;
			v[indexRm2] &= 0x80000000;
			index = indexRm1;

			// add Matsumoto-Kurita tempering
			// to get a maximally-equidistributed generator
			z4 = z4 ^ ((z4 << 7) & 0xe46e1700);
			z4 = z4 ^ ((z4 << 15) & 0x9b868000);

			l = z4;
		}
		{
			final int indexRm1 = iRm1[index];
			final int indexRm2 = iRm2[index];

			final int v0 = v[index];
			final int vM1 = v[i1[index]];
			final int vM2 = v[i2[index]];
			final int vM3 = v[i3[index]];

			final int z0 = (0x80000000 & v[indexRm1])
					^ (0x7FFFFFFF & v[indexRm2]);
			final int z1 = (v0 ^ (v0 << 25)) ^ (vM1 ^ (vM1 >>> 27));
			final int z2 = (vM2 >>> 9) ^ (vM3 ^ (vM3 >>> 1));
			final int z3 = z1 ^ z2;
			int z4 = z0 ^ (z1 ^ (z1 << 9)) ^ (z2 ^ (z2 << 21))
					^ (z3 ^ (z3 >>> 21));

			v[index] = z3;
			v[indexRm1] = z4;
			v[indexRm2] &= 0x80000000;
			index = indexRm1;

			// add Matsumoto-Kurita tempering
			// to get a maximally-equidistributed generator
			z4 = z4 ^ ((z4 << 7) & 0xe46e1700);
			z4 = z4 ^ ((z4 << 15) & 0x9b868000);

			r = z4;
		}

		return ((((long) (l >>> 6)) << 27) + (r >>> 5)) / (double) (1L << 53);

	}

	@Override
	public final Pseudorandomness copy() {
		WELL19937c copy = new WELL19937c();
		copy.reseed((ByteBuffer) this.mark.clear());

		copy.index = this.index;
		System.arraycopy(this.i1, 0, copy.i1, 0, i1.length);
		System.arraycopy(this.i2, 0, copy.i2, 0, i2.length);
		System.arraycopy(this.i3, 0, copy.i3, 0, i3.length);

		System.arraycopy(this.iRm1, 0, copy.iRm1, 0, iRm1.length);
		System.arraycopy(this.iRm2, 0, copy.iRm2, 0, iRm2.length);
		System.arraycopy(this.v, 0, copy.v, 0, v.length);

		return copy;
	}

	@Override
	public final int hashCode() {
		if (!isOpen())
			return System.identityHashCode(this);
		
		int hash = 17;

		hash = 37 * hash + M1;
		hash = 37 * hash + M2;
		hash = 37 * hash + M3;

		hash = 37 * hash + K;

		hash = 37 * hash + index;
		hash = 37 * hash + Arrays.hashCode(i1);
		hash = 37 * hash + Arrays.hashCode(i2);
		hash = 37 * hash + Arrays.hashCode(i3);

		hash = 37 * hash + Arrays.hashCode(iRm1);
		hash = 37 * hash + Arrays.hashCode(iRm2);

		return hash;
	}

	@Override
	public final boolean equals(Object obj) {
		if (obj == null)
			return false;

		if (!this.isOpen())
			return false;

		if (obj == this)
			return true;

		if (!(obj instanceof WELL19937c))
			return false;

		if (!this.toString().equals(obj.toString()))
			return false;

		WELL19937c that = (WELL19937c) obj;

		if (!that.isOpen())
			return false;

		return this.index == that.index && this.hashCode() == that.hashCode();
	}
	
	@Override
	public final String toString() {
		return PRNG.WELL19937c.name();
	}

}
