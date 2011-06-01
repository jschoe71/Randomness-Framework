package org.randomness;

import java.nio.ByteBuffer;
import java.security.SecureRandom;

/**
 * <p>
 * {Uses Java's bundled {@link SecureRandom} RNG to generate random seed data.
 * 
 * <p>
 * The advantage of using SecureRandom for seeding but not as the primary RNG is
 * that we can use it to seed RNGs that are much faster than SecureRandom. This
 * is the only seeding strategy that is guaranteed to work on all platforms.
 * 
 * @author Anton Kabysh
 * @author Daniel Dyer (uncommons-math SecureRandomSeedGenerator)
 */
final class NativeEntropy extends TruerandomnessEngine {
	/**
	 * Singleton default instance
	 */
	public static final Randomness INSTANCE = new NativeEntropy();

	/**
	 * Default instance of secure random
	 */
	SecureRandom source;

	public NativeEntropy() {
		reset();
	}

	@Override
	public final int read(final ByteBuffer buffer) {
		boolean completed = false;
		try {
			begin();

			final int remaining = buffer.remaining();
			buffer.put(source.generateSeed(remaining));
			completed = true;
			return remaining;
		} finally {
			try {
				end(completed);
			} catch (Exception e) {
				// TODO: handle exception
			}
		}
	}

	@Override
	public final byte nextByte() {
		return source.generateSeed(ONE_BYTE)[0];
	}

	// Mask for casting a byte to an int, bit-by-bit (with
	// bitwise AND) with no special consideration for the sign bit.
	private static final int BITWISE_BYTE_TO_INT = 0x000000FF;

	@Override
	public final int nextInt() {
		byte[] bytes = source.generateSeed(INT_SIZE_BYTES);
		return (BITWISE_BYTE_TO_INT & bytes[3])
				| ((BITWISE_BYTE_TO_INT & bytes[2]) << 8)
				| ((BITWISE_BYTE_TO_INT & bytes[1]) << 16)
				| ((BITWISE_BYTE_TO_INT & bytes[0]) << 24);
	}

	@Override
	public final long nextLong() {
		byte[] bytes = source.generateSeed(LONG_SIZE_BYTES);
		long value = 0;
		for (int i = 0; i < LONG_SIZE_BYTES; i++) {
			byte b = bytes[i];
			value <<= 8;
			value += b;
		}
		return value;
	}

	@Override
	protected void uninstantiate() {
		source = null;
	}

	@Override
	protected void instantiate() {
		source = new SecureRandom();
	}

	@Override
	public int minlen() {
		return -1; // TODO
	}

	@Override
	public String toString() {
		return TRNG.NATIVE.name();
	}
}