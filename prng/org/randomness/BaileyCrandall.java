/*
 * Copyright 2005, Nick Galbreath -- nickg [at] modp [dot] com
 * All rights reserved.
 * Original source code adopted to Randomness Framework by Anton Kabysh.
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
import java.util.Arrays;

/**
 * @author Nick Galbreath
 */
final class BaileyCrandall extends PseudorandomnessEngine {
	/**
	 * 
	 */
	private static final long serialVersionUID = -5968180890607220172L;

	/**
	 * Constant: 3<sup>33</sup>
	 */
	private static final double POW3_33 = 5559060566555523.0;

	/**
	 * Constant: Math.floor((3<sup>33</sup>)/2)
	 */
	private static final double POW3_33_DIV_2 = 2779530283277761.0;

	/**
	 * Constant: 2<sup>53</sup>
	 */
	private static final long POW2_53 = 9007199254740992L;

	// the iterates
	private double d1;

	// tmp variables
	private double[] dd1 = new double[2];

	private double[] dd2 = new double[2];

	private double[] dd3 = new double[2];

	/**
	 * Constructor. Seed set to current time.
	 */
	BaileyCrandall() {
		this.reset();
	}

	/**
	 * Resets internal state with new seed
	 */
	@Override
	protected final void instantiate(ByteBuffer seed) {
		// ////////////////// INSTANTIATE FUNCTION ////////////////////////
		long initial = seed.getLong();

		if (initial < POW3_33 + 100) {
			initial += POW3_33 + 100;
		}
		initial &= (POW2_53 - 1L);
		setSeedRaw(initial);

		// ////////////////// INSTANTIATE FUNCTION ////////////////////////
	}

	/**
	 * Set the raw seed or state to match original fortran code
	 * 
	 * @param seed
	 *            3<sup>33</sup>+100 <= seed < 2<sup>53</sup>
	 */
	private final void setSeedRaw(final long seed) {
		// TBD: add check, throw exception
		ddmuldd(expm2((double) seed - POW3_33, POW3_33), POW3_33_DIV_2, dd1);
		dddivd(dd1, POW3_33, dd2);
		ddmuldd(Math.floor(dd2[0]), POW3_33, dd2);
		ddsub(dd1, dd2, dd3);
		d1 = dd3[0];
	}

	/**
	 * Computes 2^p mod am
	 * 
	 * @param p
	 *            exponent
	 * @param am
	 *            modulus
	 * @return result
	 */
	private double expm2(final double p, final double am) {
		double ptl = 1;
		while (ptl < p) {
			ptl *= 2;
		}
		ptl /= 2;

		double p1 = p;
		double r = 1.0;
		double[] ddm = { am, 0.0 };
		while (true) {
			if (p1 >= ptl) {
				// r = (2*r) mod am
				ddmuldd(2.0, r, dd1);
				if (dd1[0] > am) {
					// dd1 -= ddm
					ddsub(dd1, ddm, dd2);
					dd1[0] = dd2[0];
					dd1[1] = dd2[1];
				}
				r = dd1[0];
				p1 -= ptl;
			}
			ptl *= 0.5;
			if (ptl >= 1.0) {
				/*
				 * r*r mod am == r*r - floor(r*r / am) * am
				 */
				ddmuldd(r, r, dd1);
				dddivd(dd1, am, dd2);
				ddmuldd(am, Math.floor(dd2[0]), dd2);
				ddsub(dd1, dd2, dd3);
				r = dd3[0];
				if (r < 0.0)
					r += am;
			} else {
				return r;
			}
		}
	}

	/**
	 * Used to split doubles into hi and lo words
	 */
	private static final double SPLIT = 134217729.0;

	/**
	 * Double precision multiplication
	 * 
	 * @param a
	 *            in: double
	 * @param b
	 *            in: double
	 * @param c
	 *            out: double double
	 */
	private final static void ddmuldd(final double a, final double b, double[] c) {
		double cona = a * SPLIT;
		double conb = b * SPLIT;
		double a1 = cona - (cona - a);
		double b1 = conb - (conb - b);
		double a2 = a - a1;
		double b2 = b - b1;
		double s1 = a * b;
		c[0] = s1;
		c[1] = (((a1 * b1 - s1) + a1 * b2) + a2 * b1) + a2 * b2;
		return;
	}

	/**
	 * Double Precision division
	 * 
	 * Double-double / double = double double
	 * 
	 * @param a
	 *            In: double double
	 * @param b
	 *            In: double
	 * @param c
	 *            Out: double double
	 */
	private final static void dddivd(final double[] a, final double b,
			double[] c) {
		double t1 = a[0] / b;
		double cona = t1 * SPLIT;
		double conb = b * SPLIT;
		double a1 = cona - (cona - t1);
		double b1 = conb - (conb - b);
		double a2 = t1 - a1;
		double b2 = b - b1;
		double t12 = t1 * b;
		double t22 = (((a1 * b1 - t12) + a1 * b2) + a2 * b1) + a2 * b2;
		double t11 = a[0] - t12;
		double e = t11 - a[0];
		double t21 = ((-t12 - e) + (a[0] - (t11 - e))) + a[1] - t22;
		double t2 = (t11 + t21) / b;
		double s1 = t1 + t2;
		c[0] = s1;
		c[1] = t2 - (s1 - t1);
		return;
	}

	/**
	 * Double-Precision subtraction a-b = c
	 * 
	 * @param a
	 *            in: double-double
	 * @param b
	 *            in: double-double
	 * @param c
	 *            out: double-double result
	 */
	private final static void ddsub(final double[] a, final double[] b,
			double[] c) {
		double t1 = a[0] - b[0];
		double e = t1 - a[0];
		double t2 = ((-b[0] - e) + (a[0] - (t1 - e))) + a[1] - b[1];
		double s1 = t1 + t2;
		c[0] = s1;
		c[1] = t2 - (s1 - t1);
		return;
	}

	private final double generateFloatingPoint() {
		double result = (d1 - 1.0) / (POW3_33 - 1.0);

		dd1[0] = POW2_53 * d1;
		dd1[1] = 0.0;
		dddivd(dd1, POW3_33, dd2);
		ddmuldd(POW3_33, Math.floor(dd2[0]), dd2);
		ddsub(dd1, dd2, dd3);
		d1 = dd3[0];
		if (d1 < 0.0) {
			d1 += POW3_33;
		}

		return result;
	}

	@Override
	public final int read(byte[] bytes) {
		int i = 0;
		final int iEnd = bytes.length - 3;
		while (i < iEnd) {

			if (!isOpen()) // check interruption status
				return i;

			final int random = (int) (Double
					.doubleToRawLongBits(generateFloatingPoint()) & 0x000fffffffffffffL);
			bytes[i] = (byte) (random & 0xff);
			bytes[i + 1] = (byte) ((random >> 8) & 0xff);
			bytes[i + 2] = (byte) ((random >> 16) & 0xff);
			bytes[i + 3] = (byte) ((random >> 24) & 0xff);
			i += 4;
		}

		int random = (int) (Double.doubleToRawLongBits(generateFloatingPoint()) & 0x000fffffffffffffL);
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
			double result = (d1 - 1.0) / (POW3_33 - 1.0);

			dd1[0] = POW2_53 * d1;
			dd1[1] = 0.0;
			dddivd(dd1, POW3_33, dd2);
			ddmuldd(POW3_33, Math.floor(dd2[0]), dd2);
			ddsub(dd1, dd2, dd3);
			d1 = dd3[0];
			if (d1 < 0.0) {
				d1 += POW3_33;
			}
			// ///////////////// GENERATE FUNCTION /////////////////////

			// direct inspection of iterate bits 0-51 are the mantissa
			// and should be random. 20 = 52(mantissa) - 32(int bits)
			buffer.putInt((int) ((Double.doubleToRawLongBits(result) & 0x000fffffffffffffL) >> 20));

			bytes += INT_SIZE_BYTES; // inc bytes
		}

		// transfer atomically additional bytes
		if ((numBytes - bytes) > 0) {
			// direct inspection of iterate bits 0-51 are the mantissa and
			// should be random
			int rnd = (int) (Double
					.doubleToRawLongBits(generateFloatingPoint()) & 0x000fffffffffffffL);
			// put last bytes

			for (int n = numBytes - bytes; n-- > 0; bytes++)
				buffer.put((byte) (rnd >>> (Byte.SIZE * n)));
		}

		return numBytes - buffer.remaining() /* should be zero */;
	}

	@Override
	public final int read(IntBuffer intBuffer) {

		final int numInts = intBuffer.remaining();

		for (int ints = 0; ints < numInts;) {

			if (!isOpen()) {// check interruption status
				return ints; // interrupt
			}

			// ///////////////// GENERATE FUNCTION /////////////////////
			double result = (d1 - 1.0) / (POW3_33 - 1.0);

			dd1[0] = POW2_53 * d1;
			dd1[1] = 0.0;
			dddivd(dd1, POW3_33, dd2);
			ddmuldd(POW3_33, Math.floor(dd2[0]), dd2);
			ddsub(dd1, dd2, dd3);
			d1 = dd3[0];
			if (d1 < 0.0) {
				d1 += POW3_33;
			}
			// ///////////////// GENERATE FUNCTION /////////////////////

			// direct inspection of iterate bits 0-51 are the mantissa
			// and should be random. 20 = 52(mantissa) - 32(int bits)
			intBuffer
					.put((int) ((Double.doubleToRawLongBits(result) & 0x000fffffffffffffL) >> 20));
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
			double result = (d1 - 1.0) / (POW3_33 - 1.0);

			dd1[0] = POW2_53 * d1;
			dd1[1] = 0.0;
			dddivd(dd1, POW3_33, dd2);
			ddmuldd(POW3_33, Math.floor(dd2[0]), dd2);
			ddsub(dd1, dd2, dd3);
			d1 = dd3[0];
			if (d1 < 0.0) {
				d1 += POW3_33;
			}
			// ///////////////// GENERATE FUNCTION /////////////////////
			floatBuffer.put((float) result);
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

			// ///////////////// GENERATE FUNCTION /////////////////////
			double result = (d1 - 1.0) / (POW3_33 - 1.0);

			dd1[0] = POW2_53 * d1;
			dd1[1] = 0.0;
			dddivd(dd1, POW3_33, dd2);
			ddmuldd(POW3_33, Math.floor(dd2[0]), dd2);
			ddsub(dd1, dd2, dd3);
			d1 = dd3[0];
			if (d1 < 0.0) {
				d1 += POW3_33;
			}

			int l = (int) (Double.doubleToRawLongBits(result) & 0x000fffffffffffffL);

			result = (d1 - 1.0) / (POW3_33 - 1.0);

			dd1[0] = POW2_53 * d1;
			dd1[1] = 0.0;
			dddivd(dd1, POW3_33, dd2);
			ddmuldd(POW3_33, Math.floor(dd2[0]), dd2);
			ddsub(dd1, dd2, dd3);
			d1 = dd3[0];
			if (d1 < 0.0) {
				d1 += POW3_33;
			}

			int r = (int) (Double.doubleToRawLongBits(result) & 0x000fffffffffffffL);

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

			// ///////////////// GENERATE FUNCTION /////////////////////
			double result = (d1 - 1.0) / (POW3_33 - 1.0);

			dd1[0] = POW2_53 * d1;
			dd1[1] = 0.0;
			dddivd(dd1, POW3_33, dd2);
			ddmuldd(POW3_33, Math.floor(dd2[0]), dd2);
			ddsub(dd1, dd2, dd3);
			d1 = dd3[0];
			if (d1 < 0.0) {
				d1 += POW3_33;
			}

			// ///////////////// GENERATE FUNCTION /////////////////////

			doubleBuffer.put(result);
			doubles++;
		}

		return numDoubles - doubleBuffer.remaining() /* should be zero */;
	}

	/**
	 * Returns a random value in the half-open interval [0,1) as per java spec.
	 * 
	 * @return double result
	 */
	public final double nextDouble() {
		double result = (d1 - 1.0) / (POW3_33 - 1.0);

		dd1[0] = POW2_53 * d1;
		dd1[1] = 0.0;
		dddivd(dd1, POW3_33, dd2);
		ddmuldd(POW3_33, Math.floor(dd2[0]), dd2);
		ddsub(dd1, dd2, dd3);
		d1 = dd3[0];
		if (d1 < 0.0) {
			d1 += POW3_33;
		}

		return result;

	}

	@Override
	public final float nextFloat() {
		double result = (d1 - 1.0) / (POW3_33 - 1.0);

		dd1[0] = POW2_53 * d1;
		dd1[1] = 0.0;
		dddivd(dd1, POW3_33, dd2);
		ddmuldd(POW3_33, Math.floor(dd2[0]), dd2);
		ddsub(dd1, dd2, dd3);
		d1 = dd3[0];
		if (d1 < 0.0) {
			d1 += POW3_33;
		}
		return (float) result;
	}

	@Override
	public final int nextInt() {
		double result = (d1 - 1.0) / (POW3_33 - 1.0);

		dd1[0] = POW2_53 * d1;
		dd1[1] = 0.0;
		dddivd(dd1, POW3_33, dd2);
		ddmuldd(POW3_33, Math.floor(dd2[0]), dd2);
		ddsub(dd1, dd2, dd3);
		d1 = dd3[0];
		if (d1 < 0.0) {
			d1 += POW3_33;
		}

		return (int) ((Double.doubleToRawLongBits(result) & 0x000fffffffffffffL) >> 20);
	}

	@Override
	public long nextLong() {
		double result = (d1 - 1.0) / (POW3_33 - 1.0);

		dd1[0] = POW2_53 * d1;
		dd1[1] = 0.0;
		dddivd(dd1, POW3_33, dd2);
		ddmuldd(POW3_33, Math.floor(dd2[0]), dd2);
		ddsub(dd1, dd2, dd3);
		d1 = dd3[0];
		if (d1 < 0.0) {
			d1 += POW3_33;
		}

		int l = (int) (Double.doubleToRawLongBits(result) & 0x000fffffffffffffL);

		result = (d1 - 1.0) / (POW3_33 - 1.0);

		dd1[0] = POW2_53 * d1;
		dd1[1] = 0.0;
		dddivd(dd1, POW3_33, dd2);
		ddmuldd(POW3_33, Math.floor(dd2[0]), dd2);
		ddsub(dd1, dd2, dd3);
		d1 = dd3[0];
		if (d1 < 0.0) {
			d1 += POW3_33;
		}

		int r = (int) (Double.doubleToRawLongBits(result) & 0x000fffffffffffffL);

		return ((((long) l) << 32) + r);
	}

	@Override
	public final BaileyCrandall copy() {
		BaileyCrandall bc = new BaileyCrandall();

		bc.reseed((ByteBuffer) this.mark.clear());

		bc.d1 = this.d1;

		System.arraycopy(this.dd1, 0, bc.dd1, 0, this.dd1.length);
		System.arraycopy(this.dd2, 0, bc.dd2, 0, this.dd2.length);
		System.arraycopy(this.dd3, 0, bc.dd3, 0, this.dd3.length);

		if (!isOpen())
			bc.close();

		return bc;
	}

	@Override
	public final int hashCode() {
		if (!isOpen())
			return System.identityHashCode(this);

		int hash = 17;

		hash = 37 * hash + Arrays.hashCode(dd1);
		hash = 37 * hash + Arrays.hashCode(dd2);
		hash = 37 * hash + Arrays.hashCode(dd3);

		long f = Double.doubleToLongBits(d1);
		return 37 * hash + (int) (f ^ (f >>> 32));

	}

	@Override
	public final boolean equals(Object obj) {

		if (!this.isOpen())
			return false;

		if (obj == null)
			return false;

		if (obj == null || !(obj instanceof BaileyCrandall))
			return false;

		if (obj == this)
			return true;

		BaileyCrandall that = (BaileyCrandall) obj;

		if (!that.isOpen())
			return false;

		if (Double.doubleToLongBits(this.d1) != Double
				.doubleToLongBits(that.d1))
			return false;

		if (!Arrays.equals(this.dd1, that.dd1))
			return false;

		if (!Arrays.equals(this.dd2, that.dd2))
			return false;

		if (!Arrays.equals(this.dd3, that.dd3))
			return false;

		return true;
	}

	@Override
	public final String toString() {
		return PRNG.BAILEY_CRANDALL.name();
	}

	@Override
	public final int minlen() {
		return INT_SIZE_BYTES;
	}
}