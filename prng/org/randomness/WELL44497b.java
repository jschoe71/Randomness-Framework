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

//The implementation is inspired from Apache Math's Well44497b
class WELL44497b extends WELLBase {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	/** Number of bits in the pool. */
	private static final int K = 44497;

	/** First parameter of the algorithm. */
	private static final int M1 = 23;

	/** Second parameter of the algorithm. */
	private static final int M2 = 481;

	/** Third parameter of the algorithm. */
	private static final int M3 = 229;

	WELL44497b() {
		super(K, M1, M2, M3);
		this.reset();
	}

	private final int generate32() {
		// compute raw value given by WELL44497a generator
		// which is NOT maximally-equidistributed
		final int indexRm1 = iRm1[index];
		final int indexRm2 = iRm2[index];

		final int v0 = v[index];
		final int vM1 = v[i1[index]];
		final int vM2 = v[i2[index]];
		final int vM3 = v[i3[index]];

		// the values below include the errata of the original article
		final int z0 = (0xFFFF8000 & v[indexRm1]) ^ (0x00007FFF & v[indexRm2]);
		final int z1 = (v0 ^ (v0 << 24)) ^ (vM1 ^ (vM1 >>> 30));
		final int z2 = (vM2 ^ (vM2 << 10)) ^ (vM3 << 26);
		final int z3 = z1 ^ z2;
		final int z2Prime = ((z2 << 9) ^ (z2 >>> 23)) & 0xfbffffff;
		final int z2Second = ((z2 & 0x00020000) != 0) ? (z2Prime ^ 0xb729fcec)
				: z2Prime;
		int z4 = z0 ^ (z1 ^ (z1 >>> 20)) ^ z2Second ^ z3;

		v[index] = z3;
		v[indexRm1] = z4;
		v[indexRm2] &= 0xFFFF8000;
		index = indexRm1;

		// add Matsumoto-Kurita tempering
		// to get a maximally-equidistributed generator
		z4 = z4 ^ ((z4 << 7) & 0x93dd1400);
		z4 = z4 ^ ((z4 << 15) & 0xfa118000);

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
			// compute raw value given by WELL44497a generator
			// which is NOT maximally-equidistributed
			final int indexRm1 = iRm1[index];
			final int indexRm2 = iRm2[index];

			final int v0 = v[index];
			final int vM1 = v[i1[index]];
			final int vM2 = v[i2[index]];
			final int vM3 = v[i3[index]];

			// the values below include the errata of the original article
			final int z0 = (0xFFFF8000 & v[indexRm1])
					^ (0x00007FFF & v[indexRm2]);
			final int z1 = (v0 ^ (v0 << 24)) ^ (vM1 ^ (vM1 >>> 30));
			final int z2 = (vM2 ^ (vM2 << 10)) ^ (vM3 << 26);
			final int z3 = z1 ^ z2;
			final int z2Prime = ((z2 << 9) ^ (z2 >>> 23)) & 0xfbffffff;
			final int z2Second = ((z2 & 0x00020000) != 0) ? (z2Prime ^ 0xb729fcec)
					: z2Prime;
			int z4 = z0 ^ (z1 ^ (z1 >>> 20)) ^ z2Second ^ z3;

			v[index] = z3;
			v[indexRm1] = z4;
			v[indexRm2] &= 0xFFFF8000;
			index = indexRm1;

			// add Matsumoto-Kurita tempering
			// to get a maximally-equidistributed generator
			z4 = z4 ^ ((z4 << 7) & 0x93dd1400);
			z4 = z4 ^ ((z4 << 15) & 0xfa118000);

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

			if (!isOpen()) // check interruption status
				return ints; // interrupt

			// ///////////////// GENERATE FUNCTION /////////////////////
			// compute raw value given by WELL44497a generator
			// which is NOT maximally-equidistributed
			final int indexRm1 = iRm1[index];
			final int indexRm2 = iRm2[index];

			final int v0 = v[index];
			final int vM1 = v[i1[index]];
			final int vM2 = v[i2[index]];
			final int vM3 = v[i3[index]];

			// the values below include the errata of the original article
			final int z0 = (0xFFFF8000 & v[indexRm1])
					^ (0x00007FFF & v[indexRm2]);
			final int z1 = (v0 ^ (v0 << 24)) ^ (vM1 ^ (vM1 >>> 30));
			final int z2 = (vM2 ^ (vM2 << 10)) ^ (vM3 << 26);
			final int z3 = z1 ^ z2;
			final int z2Prime = ((z2 << 9) ^ (z2 >>> 23)) & 0xfbffffff;
			final int z2Second = ((z2 & 0x00020000) != 0) ? (z2Prime ^ 0xb729fcec)
					: z2Prime;
			int z4 = z0 ^ (z1 ^ (z1 >>> 20)) ^ z2Second ^ z3;

			v[index] = z3;
			v[indexRm1] = z4;
			v[indexRm2] &= 0xFFFF8000;
			index = indexRm1;

			// add Matsumoto-Kurita tempering
			// to get a maximally-equidistributed generator
			z4 = z4 ^ ((z4 << 7) & 0x93dd1400);
			z4 = z4 ^ ((z4 << 15) & 0xfa118000);
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

			if (!isOpen()) // check interruption status
				return floats; // interrupt

			// ///////////////// GENERATE FUNCTION /////////////////////
			// compute raw value given by WELL44497a generator
			// which is NOT maximally-equidistributed
			final int indexRm1 = iRm1[index];
			final int indexRm2 = iRm2[index];

			final int v0 = v[index];
			final int vM1 = v[i1[index]];
			final int vM2 = v[i2[index]];
			final int vM3 = v[i3[index]];

			// the values below include the errata of the original article
			final int z0 = (0xFFFF8000 & v[indexRm1])
					^ (0x00007FFF & v[indexRm2]);
			final int z1 = (v0 ^ (v0 << 24)) ^ (vM1 ^ (vM1 >>> 30));
			final int z2 = (vM2 ^ (vM2 << 10)) ^ (vM3 << 26);
			final int z3 = z1 ^ z2;
			final int z2Prime = ((z2 << 9) ^ (z2 >>> 23)) & 0xfbffffff;
			final int z2Second = ((z2 & 0x00020000) != 0) ? (z2Prime ^ 0xb729fcec)
					: z2Prime;
			int z4 = z0 ^ (z1 ^ (z1 >>> 20)) ^ z2Second ^ z3;

			v[index] = z3;
			v[indexRm1] = z4;
			v[indexRm2] &= 0xFFFF8000;
			index = indexRm1;

			// add Matsumoto-Kurita tempering
			// to get a maximally-equidistributed generator
			z4 = z4 ^ ((z4 << 7) & 0x93dd1400);
			z4 = z4 ^ ((z4 << 15) & 0xfa118000);
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

				// compute raw value given by WELL44497a generator
				// which is NOT maximally-equidistributed
				final int indexRm1 = iRm1[index];
				final int indexRm2 = iRm2[index];

				final int v0 = v[index];
				final int vM1 = v[i1[index]];
				final int vM2 = v[i2[index]];
				final int vM3 = v[i3[index]];

				// the values below include the errata of the original article
				final int z0 = (0xFFFF8000 & v[indexRm1])
						^ (0x00007FFF & v[indexRm2]);
				final int z1 = (v0 ^ (v0 << 24)) ^ (vM1 ^ (vM1 >>> 30));
				final int z2 = (vM2 ^ (vM2 << 10)) ^ (vM3 << 26);
				final int z3 = z1 ^ z2;
				final int z2Prime = ((z2 << 9) ^ (z2 >>> 23)) & 0xfbffffff;
				final int z2Second = ((z2 & 0x00020000) != 0) ? (z2Prime ^ 0xb729fcec)
						: z2Prime;
				int z4 = z0 ^ (z1 ^ (z1 >>> 20)) ^ z2Second ^ z3;

				v[index] = z3;
				v[indexRm1] = z4;
				v[indexRm2] &= 0xFFFF8000;
				index = indexRm1;

				// add Matsumoto-Kurita tempering
				// to get a maximally-equidistributed generator
				z4 = z4 ^ ((z4 << 7) & 0x93dd1400);
				z4 = z4 ^ ((z4 << 15) & 0xfa118000);

				l = z4;
			}
			{

				// compute raw value given by WELL44497a generator
				// which is NOT maximally-equidistributed
				final int indexRm1 = iRm1[index];
				final int indexRm2 = iRm2[index];

				final int v0 = v[index];
				final int vM1 = v[i1[index]];
				final int vM2 = v[i2[index]];
				final int vM3 = v[i3[index]];

				// the values below include the errata of the original article
				final int z0 = (0xFFFF8000 & v[indexRm1])
						^ (0x00007FFF & v[indexRm2]);
				final int z1 = (v0 ^ (v0 << 24)) ^ (vM1 ^ (vM1 >>> 30));
				final int z2 = (vM2 ^ (vM2 << 10)) ^ (vM3 << 26);
				final int z3 = z1 ^ z2;
				final int z2Prime = ((z2 << 9) ^ (z2 >>> 23)) & 0xfbffffff;
				final int z2Second = ((z2 & 0x00020000) != 0) ? (z2Prime ^ 0xb729fcec)
						: z2Prime;
				int z4 = z0 ^ (z1 ^ (z1 >>> 20)) ^ z2Second ^ z3;

				v[index] = z3;
				v[indexRm1] = z4;
				v[indexRm2] &= 0xFFFF8000;
				index = indexRm1;

				// add Matsumoto-Kurita tempering
				// to get a maximally-equidistributed generator
				z4 = z4 ^ ((z4 << 7) & 0x93dd1400);
				z4 = z4 ^ ((z4 << 15) & 0xfa118000);

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

		for (; doubles < numDoubles; doubles++) {

			if (!isOpen()) // check interruption status
				return doubles; // interrupt

			int l;
			int r;

			// ///////////////// GENERATE FUNCTION /////////////////////
			{

				// compute raw value given by WELL44497a generator
				// which is NOT maximally-equidistributed
				final int indexRm1 = iRm1[index];
				final int indexRm2 = iRm2[index];

				final int v0 = v[index];
				final int vM1 = v[i1[index]];
				final int vM2 = v[i2[index]];
				final int vM3 = v[i3[index]];

				// the values below include the errata of the original article
				final int z0 = (0xFFFF8000 & v[indexRm1])
						^ (0x00007FFF & v[indexRm2]);
				final int z1 = (v0 ^ (v0 << 24)) ^ (vM1 ^ (vM1 >>> 30));
				final int z2 = (vM2 ^ (vM2 << 10)) ^ (vM3 << 26);
				final int z3 = z1 ^ z2;
				final int z2Prime = ((z2 << 9) ^ (z2 >>> 23)) & 0xfbffffff;
				final int z2Second = ((z2 & 0x00020000) != 0) ? (z2Prime ^ 0xb729fcec)
						: z2Prime;
				int z4 = z0 ^ (z1 ^ (z1 >>> 20)) ^ z2Second ^ z3;

				v[index] = z3;
				v[indexRm1] = z4;
				v[indexRm2] &= 0xFFFF8000;
				index = indexRm1;

				// add Matsumoto-Kurita tempering
				// to get a maximally-equidistributed generator
				z4 = z4 ^ ((z4 << 7) & 0x93dd1400);
				z4 = z4 ^ ((z4 << 15) & 0xfa118000);

				l = z4;
			}
			{

				// compute raw value given by WELL44497a generator
				// which is NOT maximally-equidistributed
				final int indexRm1 = iRm1[index];
				final int indexRm2 = iRm2[index];

				final int v0 = v[index];
				final int vM1 = v[i1[index]];
				final int vM2 = v[i2[index]];
				final int vM3 = v[i3[index]];

				// the values below include the errata of the original article
				final int z0 = (0xFFFF8000 & v[indexRm1])
						^ (0x00007FFF & v[indexRm2]);
				final int z1 = (v0 ^ (v0 << 24)) ^ (vM1 ^ (vM1 >>> 30));
				final int z2 = (vM2 ^ (vM2 << 10)) ^ (vM3 << 26);
				final int z3 = z1 ^ z2;
				final int z2Prime = ((z2 << 9) ^ (z2 >>> 23)) & 0xfbffffff;
				final int z2Second = ((z2 & 0x00020000) != 0) ? (z2Prime ^ 0xb729fcec)
						: z2Prime;
				int z4 = z0 ^ (z1 ^ (z1 >>> 20)) ^ z2Second ^ z3;

				v[index] = z3;
				v[indexRm1] = z4;
				v[indexRm2] &= 0xFFFF8000;
				index = indexRm1;

				// add Matsumoto-Kurita tempering
				// to get a maximally-equidistributed generator
				z4 = z4 ^ ((z4 << 7) & 0x93dd1400);
				z4 = z4 ^ ((z4 << 15) & 0xfa118000);

				r = z4;
			}

			doubleBuffer.put(((((long) (l >>> 6)) << 27) + (r >>> 5))
					/ (double) (1L << 53));
		}

		return numDoubles - doubleBuffer.remaining() /* should be zero */;
	}

	@Override
	public final int nextInt() {
		// compute raw value given by WELL44497a generator
		// which is NOT maximally-equidistributed
		final int indexRm1 = iRm1[index];
		final int indexRm2 = iRm2[index];

		final int v0 = v[index];
		final int vM1 = v[i1[index]];
		final int vM2 = v[i2[index]];
		final int vM3 = v[i3[index]];

		// the values below include the errata of the original article
		final int z0 = (0xFFFF8000 & v[indexRm1]) ^ (0x00007FFF & v[indexRm2]);
		final int z1 = (v0 ^ (v0 << 24)) ^ (vM1 ^ (vM1 >>> 30));
		final int z2 = (vM2 ^ (vM2 << 10)) ^ (vM3 << 26);
		final int z3 = z1 ^ z2;
		final int z2Prime = ((z2 << 9) ^ (z2 >>> 23)) & 0xfbffffff;
		final int z2Second = ((z2 & 0x00020000) != 0) ? (z2Prime ^ 0xb729fcec)
				: z2Prime;
		int z4 = z0 ^ (z1 ^ (z1 >>> 20)) ^ z2Second ^ z3;

		v[index] = z3;
		v[indexRm1] = z4;
		v[indexRm2] &= 0xFFFF8000;
		index = indexRm1;

		// add Matsumoto-Kurita tempering
		// to get a maximally-equidistributed generator
		z4 = z4 ^ ((z4 << 7) & 0x93dd1400);
		z4 = z4 ^ ((z4 << 15) & 0xfa118000);

		return z4;
	}

	@Override
	public final float nextFloat() {
		// ///////////////// GENERATE FUNCTION /////////////////////
		// compute raw value given by WELL44497a generator
		// which is NOT maximally-equidistributed
		final int indexRm1 = iRm1[index];
		final int indexRm2 = iRm2[index];

		final int v0 = v[index];
		final int vM1 = v[i1[index]];
		final int vM2 = v[i2[index]];
		final int vM3 = v[i3[index]];

		// the values below include the errata of the original article
		final int z0 = (0xFFFF8000 & v[indexRm1]) ^ (0x00007FFF & v[indexRm2]);
		final int z1 = (v0 ^ (v0 << 24)) ^ (vM1 ^ (vM1 >>> 30));
		final int z2 = (vM2 ^ (vM2 << 10)) ^ (vM3 << 26);
		final int z3 = z1 ^ z2;
		final int z2Prime = ((z2 << 9) ^ (z2 >>> 23)) & 0xfbffffff;
		final int z2Second = ((z2 & 0x00020000) != 0) ? (z2Prime ^ 0xb729fcec)
				: z2Prime;
		int z4 = z0 ^ (z1 ^ (z1 >>> 20)) ^ z2Second ^ z3;

		v[index] = z3;
		v[indexRm1] = z4;
		v[indexRm2] &= 0xFFFF8000;
		index = indexRm1;

		// add Matsumoto-Kurita tempering
		// to get a maximally-equidistributed generator
		z4 = z4 ^ ((z4 << 7) & 0x93dd1400);
		z4 = z4 ^ ((z4 << 15) & 0xfa118000);
		// ///////////////// GENERATE FUNCTION /////////////////////

		return (z4 >>> 8) / ((float) (1 << 24));
	}

	@Override
	public final long nextLong() {

		int l;
		int r;

		// ///////////////// GENERATE FUNCTION /////////////////////
		{

			// compute raw value given by WELL44497a generator
			// which is NOT maximally-equidistributed
			final int indexRm1 = iRm1[index];
			final int indexRm2 = iRm2[index];

			final int v0 = v[index];
			final int vM1 = v[i1[index]];
			final int vM2 = v[i2[index]];
			final int vM3 = v[i3[index]];

			// the values below include the errata of the original article
			final int z0 = (0xFFFF8000 & v[indexRm1])
					^ (0x00007FFF & v[indexRm2]);
			final int z1 = (v0 ^ (v0 << 24)) ^ (vM1 ^ (vM1 >>> 30));
			final int z2 = (vM2 ^ (vM2 << 10)) ^ (vM3 << 26);
			final int z3 = z1 ^ z2;
			final int z2Prime = ((z2 << 9) ^ (z2 >>> 23)) & 0xfbffffff;
			final int z2Second = ((z2 & 0x00020000) != 0) ? (z2Prime ^ 0xb729fcec)
					: z2Prime;
			int z4 = z0 ^ (z1 ^ (z1 >>> 20)) ^ z2Second ^ z3;

			v[index] = z3;
			v[indexRm1] = z4;
			v[indexRm2] &= 0xFFFF8000;
			index = indexRm1;

			// add Matsumoto-Kurita tempering
			// to get a maximally-equidistributed generator
			z4 = z4 ^ ((z4 << 7) & 0x93dd1400);
			z4 = z4 ^ ((z4 << 15) & 0xfa118000);

			l = z4;
		}
		{

			// compute raw value given by WELL44497a generator
			// which is NOT maximally-equidistributed
			final int indexRm1 = iRm1[index];
			final int indexRm2 = iRm2[index];

			final int v0 = v[index];
			final int vM1 = v[i1[index]];
			final int vM2 = v[i2[index]];
			final int vM3 = v[i3[index]];

			// the values below include the errata of the original article
			final int z0 = (0xFFFF8000 & v[indexRm1])
					^ (0x00007FFF & v[indexRm2]);
			final int z1 = (v0 ^ (v0 << 24)) ^ (vM1 ^ (vM1 >>> 30));
			final int z2 = (vM2 ^ (vM2 << 10)) ^ (vM3 << 26);
			final int z3 = z1 ^ z2;
			final int z2Prime = ((z2 << 9) ^ (z2 >>> 23)) & 0xfbffffff;
			final int z2Second = ((z2 & 0x00020000) != 0) ? (z2Prime ^ 0xb729fcec)
					: z2Prime;
			int z4 = z0 ^ (z1 ^ (z1 >>> 20)) ^ z2Second ^ z3;

			v[index] = z3;
			v[indexRm1] = z4;
			v[indexRm2] &= 0xFFFF8000;
			index = indexRm1;

			// add Matsumoto-Kurita tempering
			// to get a maximally-equidistributed generator
			z4 = z4 ^ ((z4 << 7) & 0x93dd1400);
			z4 = z4 ^ ((z4 << 15) & 0xfa118000);

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

			// compute raw value given by WELL44497a generator
			// which is NOT maximally-equidistributed
			final int indexRm1 = iRm1[index];
			final int indexRm2 = iRm2[index];

			final int v0 = v[index];
			final int vM1 = v[i1[index]];
			final int vM2 = v[i2[index]];
			final int vM3 = v[i3[index]];

			// the values below include the errata of the original article
			final int z0 = (0xFFFF8000 & v[indexRm1])
					^ (0x00007FFF & v[indexRm2]);
			final int z1 = (v0 ^ (v0 << 24)) ^ (vM1 ^ (vM1 >>> 30));
			final int z2 = (vM2 ^ (vM2 << 10)) ^ (vM3 << 26);
			final int z3 = z1 ^ z2;
			final int z2Prime = ((z2 << 9) ^ (z2 >>> 23)) & 0xfbffffff;
			final int z2Second = ((z2 & 0x00020000) != 0) ? (z2Prime ^ 0xb729fcec)
					: z2Prime;
			int z4 = z0 ^ (z1 ^ (z1 >>> 20)) ^ z2Second ^ z3;

			v[index] = z3;
			v[indexRm1] = z4;
			v[indexRm2] &= 0xFFFF8000;
			index = indexRm1;

			// add Matsumoto-Kurita tempering
			// to get a maximally-equidistributed generator
			z4 = z4 ^ ((z4 << 7) & 0x93dd1400);
			z4 = z4 ^ ((z4 << 15) & 0xfa118000);

			l = z4;
		}
		{

			// compute raw value given by WELL44497a generator
			// which is NOT maximally-equidistributed
			final int indexRm1 = iRm1[index];
			final int indexRm2 = iRm2[index];

			final int v0 = v[index];
			final int vM1 = v[i1[index]];
			final int vM2 = v[i2[index]];
			final int vM3 = v[i3[index]];

			// the values below include the errata of the original article
			final int z0 = (0xFFFF8000 & v[indexRm1])
					^ (0x00007FFF & v[indexRm2]);
			final int z1 = (v0 ^ (v0 << 24)) ^ (vM1 ^ (vM1 >>> 30));
			final int z2 = (vM2 ^ (vM2 << 10)) ^ (vM3 << 26);
			final int z3 = z1 ^ z2;
			final int z2Prime = ((z2 << 9) ^ (z2 >>> 23)) & 0xfbffffff;
			final int z2Second = ((z2 & 0x00020000) != 0) ? (z2Prime ^ 0xb729fcec)
					: z2Prime;
			int z4 = z0 ^ (z1 ^ (z1 >>> 20)) ^ z2Second ^ z3;

			v[index] = z3;
			v[indexRm1] = z4;
			v[indexRm2] &= 0xFFFF8000;
			index = indexRm1;

			// add Matsumoto-Kurita tempering
			// to get a maximally-equidistributed generator
			z4 = z4 ^ ((z4 << 7) & 0x93dd1400);
			z4 = z4 ^ ((z4 << 15) & 0xfa118000);

			r = z4;
		}

		return ((((long) (l >>> 6)) << 27) + (r >>> 5)) / (double) (1L << 53);

	}

	@Override
	public final Pseudorandomness copy() {
		WELL44497b copy = new WELL44497b();
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

		if (!(obj instanceof WELL44497b))
			return false;

		if (!this.toString().equals(obj.toString()))
			return false;

		WELL44497b that = (WELL44497b) obj;

		if (!that.isOpen())
			return false;

		return this.index == that.index && this.hashCode() == that.hashCode();
	}

	@Override
	public final String toString() {
		return PRNG.WELL44497b.name();
	}

}
