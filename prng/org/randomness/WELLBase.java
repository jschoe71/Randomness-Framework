package org.randomness;

import java.nio.ByteBuffer;

abstract class WELLBase extends PseudorandomnessEngine implements
		Pseudorandomness.Multiperiodical {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	/** Current index in the bytes pool. */
	int index;

	/** Bytes pool. */
	final int[] v;

	/**
	 * Index indirection table giving for each index its predecessor taking
	 * table size into account.
	 */
	final int[] iRm1;

	/**
	 * Index indirection table giving for each index its second predecessor
	 * taking table size into account.
	 */
	final int[] iRm2;

	/**
	 * Index indirection table giving for each index the value index + m1 taking
	 * table size into account.
	 */
	final int[] i1;

	/**
	 * Index indirection table giving for each index the value index + m2 taking
	 * table size into account.
	 */
	final int[] i2;

	/**
	 * Index indirection table giving for each index the value index + m3 taking
	 * table size into account.
	 */
	final int[] i3;

	private final int period;

	WELLBase(final int k, final int m1, final int m2, final int m3) {
		// the bits pool contains k bits, k = r w - p where r is the number
		// of w bits blocks, w is the block size (always 32 in the original
		// paper)
		// and p is the number of unused bits in the last block
		final int w = 32;
		final int r = (k + w - 1) / w;
		this.v = new int[r];
		this.index = 0;
		this.period = k;

		// precompute indirection index tables. These tables are used for
		// optimizing access
		// they allow saving computations like "(j + r - 2) % r" with costly
		// modulo operations
		iRm1 = new int[r];
		iRm2 = new int[r];
		i1 = new int[r];
		i2 = new int[r];
		i3 = new int[r];

		for (int j = 0; j < r; ++j) {
			iRm1[j] = (j + r - 1) % r;
			iRm2[j] = (j + r - 2) % r;
			i1[j] = (j + m1) % r;
			i2[j] = (j + m2) % r;
			i3[j] = (j + m3) % r;
		}
	}

	@Override
	protected final void instantiate(ByteBuffer seed) {
		// //////////////// INSTANTIATE FUNCTION ////////////////////////

		int seedints = (seed.remaining() / INT_SIZE_BYTES);
		int len = Math.min(seedints, v.length);

		// assuming that at least one zero int seed
		int zeroidx = 1; // index of last non zero seed int value

		for (int i = 0; i < len; i++) {
			v[i] = seed.getInt();

			if (v[i] != 0)
				zeroidx = (i + 1);

		}

		if (zeroidx < v.length) {
			for (int i = zeroidx; i < v.length; ++i) {
				final long l = v[i - zeroidx];
				v[i] = (int) ((1812433253l * (l ^ (l >> 30)) + i) & 0xffffffffL);
			}
		}

		index = 0;
		// //////////////// INSTANTIATE FUNCTION ////////////////////////
	}

	@Override
	public final int minlen() {
		return INT_SIZE_BYTES;
	}

	@Override
	public final int period() {
		return period;
	}

}