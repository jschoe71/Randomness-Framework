package org.randomness;

import java.nio.ByteBuffer;
import java.nio.channels.NonReadableChannelException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * CSPRNG used {@link MessageDigest} to generate random output. Based on
 * SecureRandom implementation, which use SHA1 to generate random bits.
 * <p>
 * This class adopted to {@link Cryptorandomness} interface, and source code
 * changed to support different <code>MessageDigest</code> and
 * <code>ByteBuffer</code>. This instance is internally buffered.
 * 
 * @author Anton Kabysh
 */
final class DigestCryptorandomness extends CryptorandomnessEngine {
	private static long CYCLE_COUNT = 10;

	private transient final int seedlen;
	private transient final int digestLength;
	private transient MessageDigest digest;
	/**
	 * internal state. state.length == digest.getgetDigestLength()
	 */
	private transient byte[] state;
	/**
	 * Counter for state array.
	 */
	private transient long stateCounter;

	/**
	 * internal state. state.length == digest.getgetDigestLength()
	 */
	private transient byte[] seed;
	/**
	 * Counter for seed array.
	 */
	private transient long seedCounter;

	/**
	 * Internal buffer.
	 */
	private transient byte[] remainder; // remained byte from the output.
	/**
	 * Count for remainder array.
	 */
	private transient int remCount;

	/**
	 * Construct's digest used specified algorithm and seedlen for this digest.
	 * 
	 * @param algorithm
	 *            {@link MessageDigest} algorythm.
	 * @param seedlen
	 *            seed length for this MessageDigest.
	 */
	DigestCryptorandomness(String algorithm, int seedlen) {

		try {
			digest = MessageDigest.getInstance(algorithm);
		} catch (NoSuchAlgorithmException e) {
			if (algorithm.equals("MD5"))
				digest = null;// TODO new MD5(); // internal MD5 implementation.
			else
				throw new InternalError("Internal error: " + algorithm
						+ " algorithm is not available.");

		}
		this.seedlen = seedlen;
		this.digestLength = digest.getDigestLength();

		seed = new byte[digestLength];
		state = new byte[digestLength];
		this.reset();
	}

	/**
	 * Apply specified seed to digest.
	 * 
	 * @param inSeed
	 *            final seed bytes.
	 * 
	 */
	@Override
	protected final void instantiate(ByteBuffer inSeed) {
		digest.reset();

		inSeed.rewind();
		digest.update(inSeed);
		digest.update(seed);

		seed = digest.digest();

	}

	@Override
	public final void close() {
		try {
			lock.lock();

			state = null;
			remainder = null;
			remCount = 0;

		} finally {
			lock.unlock();
		}
	}

	@Override
	public final boolean isOpen() {
		return state != null;
	}

	@Override
	public final int read(final ByteBuffer buffer) {
		if (!isOpen())
			throw new NonReadableChannelException();

		try {
			lock.lock();

			final int remaining = buffer.remaining();
			int read = 0;
			int todo;
			byte[] output = remainder;

			// Use remainder from last time
			int r = remCount;
			if (r > 0) {

				// How many bytes?
				todo = (remaining - read) < (digestLength - r) ? (remaining - read)
						: (digestLength - r);

				// Copy the bytes, bulk
				buffer.put(output, r, todo);

				// zero the buffer
				for (int i = 0; i < todo; i++) {
					output[r++] = 0;
				}

				remCount += todo;
				read += todo;

				// reach end of remainder
				if (remCount == remainder.length) {
					remCount = 0;
				}
			}

			// If we need more bytes, make them.
			while (read < remaining) {
				// Step the state
				output = generateState();

				// How many bytes?
				todo = (remaining - read) > digestLength ? digestLength
						: (remaining - read);

				// Copy the bytes,
				buffer.put(output, 0, todo);

				// zero the buffer
				for (int i = 0; i < todo; i++) {
					output[i] = 0;
				}

				read += todo;
				remCount += todo;
			}

			// Store remainder for next time
			remainder = output;
			// remCount %= digestLength;

			read = remaining - buffer.remaining() /* should be zero */;
			byteCounter += read;

			return read;
		} finally {
			lock.unlock();
		}
	}

	private final byte[] generateState() {
		byte[] output = null;
		try {
			digest.update(longToByteArray(stateCounter++));
			digest.update(state);
			digest.update(seed);
			return output = digest.digest();
		} finally {
			updateState(state, output);

			if ((stateCounter % CYCLE_COUNT) == 0) {
				// cycle seed
				digest.update(seed);
				digest.update(longToByteArray(seedCounter++));
				seed = digest.digest();
			}
		}
	}

	@Override
	public final int seedlen() {
		return seedlen;
	}

	@Override
	public final int minlen() {
		return digestLength;
	}

	@Override
	public final String toString() {
		return "CSPRNG." + digest.getAlgorithm();
	}

	private static void updateState(byte[] state, byte[] output) {
		int last = 1;
		int v = 0;
		byte t = 0;
		boolean zf = false;

		// state(n + 1) = (state(n) + output(n) + 1) % 2^160;
		for (int i = 0; i < state.length; i++) {
			// Add two bytes
			v = (int) state[i] + (int) output[i] + last;
			// Result is lower 8 bits
			t = (byte) v;
			// Store result. Check for state collision.
			zf = zf | (state[i] != t);
			state[i] = t;
			// High 8 bits are carry. Store for next iteration.
			last = v >> 8;
		}

		// Make sure at least one bit changes!
		if (!zf)
			state[0]++;
	}

	public static void main(String[] args) {
		DigestCryptorandomness dg = new DigestCryptorandomness("SHA-256", 111);
		System.out.println(dg.digest.getDigestLength());
		for (int i = 0; i < 100; i++) {
			System.out.println(dg.nextInt());
		}
	}
}