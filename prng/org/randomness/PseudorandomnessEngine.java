package org.randomness;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import org.apache.commons.math.util.FastMath;

abstract class PseudorandomnessEngine extends Pseudorandomness {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	/**
	 * Indicate if generator is shared or not.
	 */
	final boolean shared;

	/**
	 * Length of seed in bytes
	 */
	private final int seedlen;

	/**
	 * Marked working state.
	 */
	ByteBuffer mark;

	private final Object markLock = new Object();

	public PseudorandomnessEngine() {
		this.seedlen = PRNG.valueOf(toString()).seedlen();
		shared = true;
	}

	@Override
	public final void reset() {
		if (mark == null) {
			this.reseed(ByteBuffer.wrap(getEntropyInput(seedlen)));
		} else
			this.reseed((ByteBuffer) mark.clear());
	}

	@Override
	public final Pseudorandomness reseed(final ByteBuffer seed) {
		if (seed == null || seed.remaining() < seedlen) {
			throw new IllegalArgumentException(toString() + " requires a "
					+ seedlen + " bytes seed.");
		}

		// synchronize to protect from asynchronous closability.
		// guaranteed, that instantiate function will complete normal.
		synchronized (markLock) {
			if (mark == null || seed != mark) {
				final byte[] markBytes = new byte[seedlen];
				seed.get(markBytes);
				mark = ByteBuffer.wrap(markBytes);
				// to ensure predictable seed on every platform
				mark.order(ByteOrder.BIG_ENDIAN);
			}

			this.instantiate((ByteBuffer) mark.clear());
			mark.clear();

		}

		return this;
	}

	/**
	 * Apply current seed bytes to create <i>initial working state</i>.
	 * 
	 * @param seed
	 *            the seed bytes
	 * 
	 */
	protected abstract void instantiate(ByteBuffer seed);

	@Override
	public final boolean isOpen() {
		return mark != null;
	}

	@Override
	public final void close() {
		synchronized (markLock) {
			// synchronized with instantiate function
			mark = null; // close and interrupt channel, if proceed
		}
	}

	@Override
	protected final int seedlen() {
		return PRNG.valueOf(toString()).seedlen();
	}

	@Override
	public int tryRead(ByteBuffer buffer) {
		return this.read(buffer);
	}

	
}
