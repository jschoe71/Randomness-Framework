package org.randomness;

import java.nio.ByteBuffer;
import java.nio.channels.NonReadableChannelException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * Cryptorandomness wrapper over <code>java.security.SecureRandom</code>.
 * 
 * @author Anton Kabysh
 * 
 */
final class SecureCryptorandomness extends CryptorandomnessEngine {
	/**
	 * Secure Random generator
	 */
	transient SecureRandom random;
	/**
	 * Length of SecureRandom seed.
	 */
	private transient final int seedlen;

	/**
	 * Indicate if this RNG is open to produce randomness.
	 */
	boolean open = true;

	/**
	 * Create Native Pseurorandom Number Generator
	 */
	public SecureCryptorandomness() {
		random = new SecureRandom(); // Native
		this.seedlen = CSPRNG.NATIVE.seedlen.get();
		this.reset();
	}

	/**
	 * Constructs SecureRandom Number generator using specified algorithm.
	 * 
	 * @param algorithm
	 *            the algorithm name.
	 * @param seedlen
	 *            seed length in bytes.
	 */
	SecureCryptorandomness(String algorithm, int seedlen) {

		try {
			random = SecureRandom.getInstance(algorithm);
		} catch (NoSuchAlgorithmException e) {
			throw new InternalError("NoSuchAlgorithmException: " + algorithm
					+ " algorithm is not available.");
		}
		this.seedlen = seedlen;

		// instantiate function
		this.reset();
	}

	@Override
	protected final void instantiate(ByteBuffer seed) {
		seed.rewind();
		random.setSeed(bufferToArray(seed));
	}

	public final boolean isOpen() {
		return open;
	}

	@Override
	public final void close() {
		open = false;
	}

	@Override
	protected byte[] getEntropyInput(int min_entropy, int min_length,
			int max_length) {
		if (min_entropy < 0)
			throw new IllegalArgumentException(ENTROPY_INPUT_ERRORS[0]);
		if (min_entropy < securityStrength())
			throw new IllegalArgumentException(ENTROPY_INPUT_ERRORS[1]);
		if (min_length < min_entropy)
			throw new IllegalArgumentException(ENTROPY_INPUT_ERRORS[2]);
		if (min_length < seedlen())
			throw new IllegalArgumentException(ENTROPY_INPUT_ERRORS[3]);
		if (min_length > max_length)
			throw new IllegalArgumentException(ENTROPY_INPUT_ERRORS[4]);
		if (max_length > CSPRNG.MAX_ENTROPY_INPUT_LENGTH.get())
			throw new IllegalArgumentException(ENTROPY_INPUT_ERRORS[5]);

		return random.generateSeed(min_length);
	}

	@Override
	public final int read(final ByteBuffer buffer) {
		if (!isOpen())
			throw new NonReadableChannelException();

		final int rem = buffer.remaining();
		final byte[] randomBytes = new byte[rem];

		try {
			lock.lock();

			random.nextBytes(randomBytes); // read random bytes

			buffer.put(randomBytes);

			byteCounter += (rem - buffer.remaining());
			return rem - buffer.remaining() /* should be zero */;
		} finally {
			lock.unlock();
		}
	}

	@Override
	public final int seedlen() {
		return seedlen;
	}

	@Override
	public final String toString() {
		return "CSPRNG." + random.getAlgorithm();
	}

	@Override
	public final int nextInt() {
		return random.nextInt();
	}

	@Override
	public final long nextLong() {
		return random.nextLong();
	}

	@Override
	public final float nextFloat() {
		return random.nextFloat();
	}

	@Override
	public final double nextDouble() {
		return random.nextDouble();
	}

	@Override
	public final boolean nextBoolean() {
		return random.nextBoolean();
	}

	@Override
	public final int minlen() {
		return 0; // not specified.
	}
}
