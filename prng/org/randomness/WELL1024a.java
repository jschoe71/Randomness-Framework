/*
 * Adopted to randomness framework by Anton Kabysh.
 * 
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.randomness;

import java.nio.ByteBuffer;
import java.nio.DoubleBuffer;
import java.nio.FloatBuffer;
import java.nio.IntBuffer;
import java.nio.LongBuffer;
import java.util.Arrays;

// The implementation is inspired from Apache Math's Well1024a
public final class WELL1024a extends WELLBase {
	/** Serializable version identifier. */
	private static final long serialVersionUID = 5680173464174485492L;

	/** Number of bits in the pool. */
	private static final int K = 1024;

	/** First parameter of the algorithm. */
	private static final int M1 = 3;

	/** Second parameter of the algorithm. */
	private static final int M2 = 24;

	/** Third parameter of the algorithm. */
	private static final int M3 = 10;

	public WELL1024a() {
		super(K, M1, M2, M3);
		this.reset();
	}

	private int generate32() {
		final int indexRm1 = iRm1[index];

		final int v0 = v[index];
		final int vM1 = v[i1[index]];
		final int vM2 = v[i2[index]];
		final int vM3 = v[i3[index]];

		final int z0 = v[indexRm1];
		final int z1 = v0 ^ (vM1 ^ (vM1 >>> 8));
		final int z2 = (vM2 ^ (vM2 << 19)) ^ (vM3 ^ (vM3 << 14));
		final int z3 = z1 ^ z2;
		final int z4 = (z0 ^ (z0 << 11)) ^ (z1 ^ (z1 << 7)) ^ (z2 ^ (z2 << 13));

		v[index] = z3;
		v[indexRm1] = z4;
		index = indexRm1;

		return z4;
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
			final int indexRm1 = iRm1[index];

			final int v0 = v[index];
			final int vM1 = v[i1[index]];
			final int vM2 = v[i2[index]];
			final int vM3 = v[i3[index]];

			final int z0 = v[indexRm1];
			final int z1 = v0 ^ (vM1 ^ (vM1 >>> 8));
			final int z2 = (vM2 ^ (vM2 << 19)) ^ (vM3 ^ (vM3 << 14));
			final int z3 = z1 ^ z2;
			final int z4 = (z0 ^ (z0 << 11)) ^ (z1 ^ (z1 << 7))
					^ (z2 ^ (z2 << 13));

			v[index] = z3;
			v[indexRm1] = z4;
			index = indexRm1;
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
	public int read(IntBuffer intBuffer) {

		final int numInts = intBuffer.remaining();

		int ints = 0;

		for (; ints < numInts;) {

			if (!isOpen()) // check interruption status
				return ints; // interrupt

			// ///////////////// GENERATE FUNCTION /////////////////////
			// Set cell addresses using address of current cell.
			final int indexRm1 = iRm1[index];

			final int v0 = v[index];
			final int vM1 = v[i1[index]];
			final int vM2 = v[i2[index]];
			final int vM3 = v[i3[index]];

			final int z0 = v[indexRm1];
			final int z1 = v0 ^ (vM1 ^ (vM1 >>> 8));
			final int z2 = (vM2 ^ (vM2 << 19)) ^ (vM3 ^ (vM3 << 14));
			final int z3 = z1 ^ z2;
			final int z4 = (z0 ^ (z0 << 11)) ^ (z1 ^ (z1 << 7))
					^ (z2 ^ (z2 << 13));

			v[index] = z3;
			v[indexRm1] = z4;
			index = indexRm1;
			// ///////////////// GENERATE FUNCTION /////////////////////

			intBuffer.put(z4);
			ints++;
		}

		return numInts - intBuffer.remaining();
	}

	@Override
	public int read(FloatBuffer floatBuffer) {

		final int numFloats = floatBuffer.remaining();

		int floats = 0;

		for (; floats < numFloats;) {

			if (!isOpen()) // check interruption status
				return floats; // interrupt

			// ///////////////// GENERATE FUNCTION /////////////////////
			// Set cell addresses using address of current cell.
			final int indexRm1 = iRm1[index];

			final int v0 = v[index];
			final int vM1 = v[i1[index]];
			final int vM2 = v[i2[index]];
			final int vM3 = v[i3[index]];

			final int z0 = v[indexRm1];
			final int z1 = v0 ^ (vM1 ^ (vM1 >>> 8));
			final int z2 = (vM2 ^ (vM2 << 19)) ^ (vM3 ^ (vM3 << 14));
			final int z3 = z1 ^ z2;
			final int z4 = (z0 ^ (z0 << 11)) ^ (z1 ^ (z1 << 7))
					^ (z2 ^ (z2 << 13));

			v[index] = z3;
			v[indexRm1] = z4;
			index = indexRm1;
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

			if (!isOpen()) // check interruption status
				return longs; // interrupt

			int l;
			int r;

			// ///////////////// GENERATE FUNCTION /////////////////////
			{
				final int indexRm1 = iRm1[index];

				final int v0 = v[index];
				final int vM1 = v[i1[index]];
				final int vM2 = v[i2[index]];
				final int vM3 = v[i3[index]];

				final int z0 = v[indexRm1];
				final int z1 = v0 ^ (vM1 ^ (vM1 >>> 8));
				final int z2 = (vM2 ^ (vM2 << 19)) ^ (vM3 ^ (vM3 << 14));
				final int z3 = z1 ^ z2;
				final int z4 = (z0 ^ (z0 << 11)) ^ (z1 ^ (z1 << 7))
						^ (z2 ^ (z2 << 13));

				v[index] = z3;
				v[indexRm1] = z4;
				index = indexRm1;

				l = z4;
			}
			{
				final int indexRm1 = iRm1[index];

				final int v0 = v[index];
				final int vM1 = v[i1[index]];
				final int vM2 = v[i2[index]];
				final int vM3 = v[i3[index]];

				final int z0 = v[indexRm1];
				final int z1 = v0 ^ (vM1 ^ (vM1 >>> 8));
				final int z2 = (vM2 ^ (vM2 << 19)) ^ (vM3 ^ (vM3 << 14));
				final int z3 = z1 ^ z2;
				final int z4 = (z0 ^ (z0 << 11)) ^ (z1 ^ (z1 << 7))
						^ (z2 ^ (z2 << 13));

				v[index] = z3;
				v[indexRm1] = z4;
				index = indexRm1;

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

			if (!isOpen()) // check interruption status
				return doubles; // interrupt

			int l;
			int r;

			// ///////////////// GENERATE FUNCTION /////////////////////
			{
				final int indexRm1 = iRm1[index];

				final int v0 = v[index];
				final int vM1 = v[i1[index]];
				final int vM2 = v[i2[index]];
				final int vM3 = v[i3[index]];

				final int z0 = v[indexRm1];
				final int z1 = v0 ^ (vM1 ^ (vM1 >>> 8));
				final int z2 = (vM2 ^ (vM2 << 19)) ^ (vM3 ^ (vM3 << 14));
				final int z3 = z1 ^ z2;
				final int z4 = (z0 ^ (z0 << 11)) ^ (z1 ^ (z1 << 7))
						^ (z2 ^ (z2 << 13));

				v[index] = z3;
				v[indexRm1] = z4;
				index = indexRm1;

				l = z4;
			}
			{
				final int indexRm1 = iRm1[index];

				final int v0 = v[index];
				final int vM1 = v[i1[index]];
				final int vM2 = v[i2[index]];
				final int vM3 = v[i3[index]];

				final int z0 = v[indexRm1];
				final int z1 = v0 ^ (vM1 ^ (vM1 >>> 8));
				final int z2 = (vM2 ^ (vM2 << 19)) ^ (vM3 ^ (vM3 << 14));
				final int z3 = z1 ^ z2;
				final int z4 = (z0 ^ (z0 << 11)) ^ (z1 ^ (z1 << 7))
						^ (z2 ^ (z2 << 13));

				v[index] = z3;
				v[indexRm1] = z4;
				index = indexRm1;

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

		final int v0 = v[index];
		final int vM1 = v[i1[index]];
		final int vM2 = v[i2[index]];
		final int vM3 = v[i3[index]];

		final int z0 = v[indexRm1];
		final int z1 = v0 ^ (vM1 ^ (vM1 >>> 8));
		final int z2 = (vM2 ^ (vM2 << 19)) ^ (vM3 ^ (vM3 << 14));
		final int z3 = z1 ^ z2;
		final int z4 = (z0 ^ (z0 << 11)) ^ (z1 ^ (z1 << 7)) ^ (z2 ^ (z2 << 13));

		v[index] = z3;
		v[indexRm1] = z4;
		index = indexRm1;

		return z4;
	}

	@Override
	public final float nextFloat() {
		final int indexRm1 = iRm1[index];

		final int v0 = v[index];
		final int vM1 = v[i1[index]];
		final int vM2 = v[i2[index]];
		final int vM3 = v[i3[index]];

		final int z0 = v[indexRm1];
		final int z1 = v0 ^ (vM1 ^ (vM1 >>> 8));
		final int z2 = (vM2 ^ (vM2 << 19)) ^ (vM3 ^ (vM3 << 14));
		final int z3 = z1 ^ z2;
		final int z4 = (z0 ^ (z0 << 11)) ^ (z1 ^ (z1 << 7)) ^ (z2 ^ (z2 << 13));

		v[index] = z3;
		v[indexRm1] = z4;
		index = indexRm1;

		return (z4 >>> 8) / ((float) (1 << 24));
	}

	@Override
	public final long nextLong() {
		int l;
		int r;

		{
			final int indexRm1 = iRm1[index];

			final int v0 = v[index];
			final int vM1 = v[i1[index]];
			final int vM2 = v[i2[index]];
			final int vM3 = v[i3[index]];

			final int z0 = v[indexRm1];
			final int z1 = v0 ^ (vM1 ^ (vM1 >>> 8));
			final int z2 = (vM2 ^ (vM2 << 19)) ^ (vM3 ^ (vM3 << 14));
			final int z3 = z1 ^ z2;
			final int z4 = (z0 ^ (z0 << 11)) ^ (z1 ^ (z1 << 7))
					^ (z2 ^ (z2 << 13));

			v[index] = z3;
			v[indexRm1] = z4;
			index = indexRm1;

			l = z4;
		}
		{
			final int indexRm1 = iRm1[index];

			final int v0 = v[index];
			final int vM1 = v[i1[index]];
			final int vM2 = v[i2[index]];
			final int vM3 = v[i3[index]];

			final int z0 = v[indexRm1];
			final int z1 = v0 ^ (vM1 ^ (vM1 >>> 8));
			final int z2 = (vM2 ^ (vM2 << 19)) ^ (vM3 ^ (vM3 << 14));
			final int z3 = z1 ^ z2;
			final int z4 = (z0 ^ (z0 << 11)) ^ (z1 ^ (z1 << 7))
					^ (z2 ^ (z2 << 13));

			v[index] = z3;
			v[indexRm1] = z4;
			index = indexRm1;

			r = z4;
		}

		return (((long) l) << 32) + r;
	}

	@Override
	public final double nextDouble() {
		int l;
		int r;

		{
			final int indexRm1 = iRm1[index];

			final int v0 = v[index];
			final int vM1 = v[i1[index]];
			final int vM2 = v[i2[index]];
			final int vM3 = v[i3[index]];

			final int z0 = v[indexRm1];
			final int z1 = v0 ^ (vM1 ^ (vM1 >>> 8));
			final int z2 = (vM2 ^ (vM2 << 19)) ^ (vM3 ^ (vM3 << 14));
			final int z3 = z1 ^ z2;
			final int z4 = (z0 ^ (z0 << 11)) ^ (z1 ^ (z1 << 7))
					^ (z2 ^ (z2 << 13));

			v[index] = z3;
			v[indexRm1] = z4;
			index = indexRm1;

			l = z4;
		}
		{
			final int indexRm1 = iRm1[index];

			final int v0 = v[index];
			final int vM1 = v[i1[index]];
			final int vM2 = v[i2[index]];
			final int vM3 = v[i3[index]];

			final int z0 = v[indexRm1];
			final int z1 = v0 ^ (vM1 ^ (vM1 >>> 8));
			final int z2 = (vM2 ^ (vM2 << 19)) ^ (vM3 ^ (vM3 << 14));
			final int z3 = z1 ^ z2;
			final int z4 = (z0 ^ (z0 << 11)) ^ (z1 ^ (z1 << 7))
					^ (z2 ^ (z2 << 13));

			v[index] = z3;
			v[indexRm1] = z4;
			index = indexRm1;

			r = z4;
		}

		return ((((long) (l >>> 6)) << 27) + (r >>> 5)) / (double) (1L << 53);

	}

	@Override
	public final Pseudorandomness copy() {
		WELL1024a copy = new WELL1024a();
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

		if (!(obj instanceof WELL1024a))
			return false;

		if (!this.toString().equals(obj.toString()))
			return false;

		WELL1024a that = (WELL1024a) obj;

		if (!that.isOpen())
			return false;

		return this.index == that.index && this.hashCode() == that.hashCode();
	}

	@Override
	public final String toString() {
		return PRNG.WELL1024a.name();
	}
}
