package org.randomness;

import java.nio.ByteBuffer;
import java.nio.DoubleBuffer;
import java.nio.FloatBuffer;
import java.nio.IntBuffer;
import java.nio.LongBuffer;

@SuppressWarnings("unused")
class dSFMT2 extends PseudorandomnessEngine {
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
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
	private final static int N = (MEXP - 128) / 104 + 1;
	/**
	 * <code>N32</code> is the size of internal state array when regarded as an
	 * array of 32-bit integers.
	 */
	private final static int N32 = N * 4;
	/**
	 * <code>N64</code> is the size of internal state array when regarded as an
	 * array of 64-bit integers.
	 */
	private final static int N64 = N * 2;

	/**
	 * The pick up position of the array.
	 */
	private static final int POS1 = 117;
	/**
	 * The parameter of shift left as four 32-bit registers.
	 */
	private static final int SL1 = 19;

	/**
	 * A bitmask, used in the recursion. These parameters are introduced to
	 * break symmetry of SIMD.
	 */
	private static final long MSK1 = 0x000ffafffffffb3fL;
	private static final long MSK2 = 0x000ffdfffc90fffdL;

	private static final int MSK32_1 = 0x000ffaff;
	private static final int MSK32_2 = 0xfffffb3f;
	private static final int MSK32_3 = 0x000ffdff;
	private static final int MSK32_4 = 0xfc90fffd;

	private static final long FIX1 = 0x90014964b32f4329L;
	private static final long FIX2 = 0x3b8d12ac548a7c7aL;

	/* These definitions are part of a 128-bit period certification vector. */
	private static final long PCV1 = 0x3d84e1ac0dc82880L;
	private static final long PCV2 = 0x0000000000000001L;

	private static final String IDSTR = "dSFMT2-19937:117-19:ffafffffffb3f-ffdfffc90fffd";

	private static final long LOW_MASK = 0x000FFFFFFFFFFFFFL;
	private static final long HIGH_CONST = 0x3FF0000000000000L;
	private static final int SR = 12;

	/** 128-bit data structure */
	private static class W128_T {
		long[] u = new long[2];
		int[] u32 = new int[4];
		double[] d = new double[2];
	}

	/** the 128-bit internal state array */
	W128_T[] status = new W128_T[N + 1];

	int idx;

	public dSFMT2() {
		this.reset();
	}

	/**
	 * This function generates and returns unsigned 32-bit integer. This is
	 * slower than SFMT, only for convenience usage. dsfmt_init_gen_rand() or
	 * dsfmt_init_by_array() must be called before this function.
	 * 
	 * @param dsfmt
	 *            dsfmt internal state date
	 * @return double precision floating point pseudorandom number
	 */
	@Override
	public int nextInt() {
		int r = 0;
		long[] psfmt64 = status[0].u;

		if (idx >= N64) {
			// dsfmt_gen_rand_all(dsfmt);
			idx = 0;
		}
		// r = psfmt64[idx++] & 0xffffffff;
		return r;
	}

	@Override
	public String toString() {
		return "SFMT2" + MEXP;
	}

	public static void main(String[] args) {
		System.out.println(N);
	}

	@Override
	protected void instantiate(ByteBuffer seed) {

	}

	@Override
	public int hashCode() {
		if (!isOpen())
			return System.identityHashCode(this);

		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	public boolean equals(Object obj) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public Pseudorandomness copy() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public int read(ByteBuffer buffer) {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	public int read(IntBuffer intBuffer) {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	public int read(FloatBuffer floatBuffer) {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	public int read(LongBuffer longBuffer) {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	public int read(DoubleBuffer doubleBuffer) {
		// TODO Auto-generated method stub
		return 0;
	}
}
