package org.randomness;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.channels.NonReadableChannelException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Random;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Internal implementation of {@link Cryptorandomness} abstract class for 32-bit
 * cryptographically pseudarandom number generators used hash based
 * <i>derivation function</i>.
 * <p>
 * During instantiation, an initial internal state is derived from the seed. The
 * internal state for an instantiation includes:
 * <ol>
 * <li>Working state:
 * <ul>
 * <li>a. One or more values that are derived from the seed and become part of
 * the internal state; these values should remain secret, and
 * <li>b. A count of the number of requests or blocks produced since the
 * instantiation was seeded or reseeded.
 * </ul>
 * 2. Administrative information (e.g., security strength and prediction
 * resistance flag).
 * </ol>
 * 
 * @author Anton Kabysh
 * 
 */
abstract class CryptorandomnessEngine extends Cryptorandomness {
	// Lock to prevent concurrent modification of the RNG's internal state.
	final ReentrantLock lock = new ReentrantLock();
	/**
	 * Counter of random bytes, produced by this RBG since the instantiation.
	 * Number of random bytes produced since the instantiation was seeded or
	 * reseeded. Used as a part of Working state.
	 */
	int byteCounter = 0;

	// Nonce object
	private transient Nonce nonce;

	// 10.4.1 Derivation Function Using a Hash Function (Hash_df) - p.65
	private transient HashDf hash;

	/**
	 * ByteBuffer to read long and int values. To prevent unnecessary
	 * allocation.
	 */
	private final ByteBuffer intBytes = ByteBuffer.allocate(INT_SIZE_BYTES);
	private final ByteBuffer longBytes = ByteBuffer.allocate(LONG_SIZE_BYTES);

	protected CryptorandomnessEngine() {
		super(null);
	}

	/**
	 * Create seed for <b>instantiate function</b>.
	 * 
	 * @return instantiate seed bytes
	 */
	@Override
	public final void reset() {
		try {
			lock.lock();
			nonce = new Nonce();
			// 10.4.1 Derivation Function Using a Hash Function (Hash_df) - p.65
			hash = new HashDf();

			// 4. 9.1 Instantiating a DRBG - p. 23.
			byte[] entropy = getEntropyInput(seedlen());

			// 5. Nonce - is a time-varying value that has at most a negligible
			// chance of repeating with 1/2 security_strength bytes of entropy
			final byte[] nonceBytes = nonce();

			// 6 Obtain a pers. string
			final byte[] persnBytes = personalizationString.toByteArray();

			// initial_working_state = Instantiate_algorithm (entropy_input,
			// nonce, personalization_string).
			// where Instantiate_algorithm = Hash_DRBG_Instantiate_algorithm;

			// 7. Hash_DRBG_Instantiate_algorithm, p 36-37:
			// seed_material = entropy_input || nonce || personalization_string
			ByteBuffer seedMaterial = ByteBuffer.allocate(entropy.length
					+ nonceBytes.length + persnBytes.length);

			seedMaterial.put(entropy);
			seedMaterial.put(nonceBytes);
			seedMaterial.put(persnBytes);

			// seed = Hash_df (seed_material, seedlen) where seedlen == size();
			// 7. create initial_working_state using specified seed.
			instantiate(hash.generate(seedMaterial));
		} finally {
			byteCounter = 0;
			lock.unlock();
		}

	}

	@Override
	public final void reseed(ByteBuffer additionalInput) {

		if (additionalInput != null) {
			additionalInput.rewind();

			if (additionalInput.remaining() > CSPRNG.MAX_ENTROPY_INPUT_LENGTH
					.get())
				throw new IllegalArgumentException(
						"The length of the additional_input > max_additional_input_length.");
		} else {
			// internal additional entropy
			final byte[] nonceBytes = nonce();
			final byte[] persnBytes = personalizationString.toByteArray();
			additionalInput = ByteBuffer.allocate(nonceBytes.length
					+ persnBytes.length);
			additionalInput.put(nonceBytes).put(persnBytes);
			additionalInput.rewind();
		}

		try {
			lock.lock();

			// 3. Obtain the entropy input
			// entropy_input = Get_entropy_input (security_strength,
			// min_length, max_length).
			byte[] entropy_input = getEntropyInput(seedlen());

			// 5. new_working_state = Reseed_algorithm (working_state,
			// entropy_input, additional_input).
			ByteBuffer seed_material = ByteBuffer.allocate(INT_SIZE_BYTES
					+ entropy_input.length + additionalInput.remaining());

			seed_material.putInt(byteCounter); // part of working state.
			seed_material.put(entropy_input);
			seed_material.put(additionalInput);

			// seed = Hash_df (seed_material, seedlen).
			instantiate(hash.generate(seed_material));
		} finally {
			byteCounter = 0;
			nonce.reset();
			hash.reset();
			lock.unlock();
		}
	}

	@Override
	public int nextInt() {
		read((ByteBuffer) intBytes.clear());
		return ((ByteBuffer) intBytes.flip()).getInt();
	}

	@Override
	public int tryRead(ByteBuffer buffer) {
		throw new UnsupportedOperationException();
	}

	@Override
	public long nextLong() {
		read((ByteBuffer) longBytes.clear());
		return ((ByteBuffer) longBytes.rewind()).getLong();
	}

	@Override
	protected byte[] nonce() {
		return nonce.generate();
	}

	protected abstract void instantiate(ByteBuffer seed);

	/**
	 * The hash-based derivation function used to create cryptographic seed from
	 * specified entropy input, cryptographic source and, hashes an input string
	 * and returns the requested number of bits.
	 * 
	 * I suppose, that this implementation is need to be analyzed.
	 * 
	 * @author Anton Kabysh
	 * 
	 */
	private class HashDf {
		/**
		 * Let Hash be the hash function used by the DRBG mechanism, and let
		 * outlen be its output length
		 */
		private transient MessageDigest hash;

		private transient int counter;

		private HashDf() {
			this.reset();
		}

		public void reset() {
			try {
				String algorithm = defineSecureHashAlgorithm(securityStrength());
				hash = MessageDigest.getInstance(algorithm);
			} catch (NoSuchAlgorithmException e) {
				// TODO
			}
			counter = ByteBuffer.wrap(
					hash.digest(longToByteArray(System.nanoTime()))).getInt();
		}

		/**
		 * Process seed_material into cryptographic seed.<br>
		 * 
		 * 
		 * @param seed_material
		 *            = entropy_input || nonce || personalization_string<br>
		 *            , where || - is a concatenation.
		 * @return The result bytes of performing the Hash_df
		 */
		// 10.4.1 Derivation Function Using a Hash Function (Hash_df) - p. 65
		public ByteBuffer generate(ByteBuffer seed_material) {
			int no_of_bytes_to_return = seedlen();
			final int len = hash.getDigestLength();

			ByteBuffer seed = ByteBuffer.allocate(no_of_bytes_to_return);
			int numBytes;
			while (seed.hasRemaining()) {
				seed_material.rewind();
				numBytes = Math.min(seed.remaining(), len);

				// Hash (counter || no_of_bits_to_return || input_string).
				hash.update((byte) counter);
				hash.update(BigInteger.valueOf(no_of_bytes_to_return)
						.toByteArray());
				hash.update(seed_material);

				seed.put(hash.digest(), 0, numBytes);

				// to be more variable
				no_of_bytes_to_return -= seed.position();
			}

			return (ByteBuffer) seed.rewind();
		}

		@Override
		public String toString() {
			return "RBG.HASH_DERIVATION_FUNCTION";
		}
	}

	/**
	 * This class represents a cryptographic nonce randomness. <i>Nonce</i> - is
	 * a time-varying value that has at most a negligible chance of repeating,
	 * e.g., a random value that is generated anew for each use, a timestamp, a
	 * sequence number, or some combination of these.
	 * 
	 * Hash_df in counter mode, as a nonce function. I suppose, that this
	 * implementation is need to be analyzed and tested.
	 * 
	 * @author Anton Kabysh
	 * 
	 */
	private final class Nonce extends Truerandomness {
		/**
		 * Nonce base bytes
		 */
		private byte[] nonce;
		/**
		 * Hash function
		 */
		private MessageDigest digest;
		/**
		 * hash counter
		 */
		private int counter;
		/**
		 * Current nonce size in bytes.
		 */
		private final int size;

		private Nonce() {
			size = Math.round((float) (securityStrength() * 0.5));
			this.reset();
		}

		final byte[] generate() {
			try {
				return nonce;
			} finally {
				int read = 0;
				while (read < nonce.length) {
					digest.update((byte) ++counter);
					digest.update((byte) System.currentTimeMillis());
					digest.update(nonce);
					byte[] output = digest.digest();
					int todo = Math.min(output.length, nonce.length - read);
					System.arraycopy(output, 0, nonce, read, todo);
					read += todo;
				}
			}
		}

		@Override
		public final int read(ByteBuffer buffer) {
			int bytesToRead, requiredBytes = buffer.remaining();

			while (buffer.hasRemaining()) {
				bytesToRead = Math.min(buffer.remaining(), size);
				buffer.put(generate(), 0, bytesToRead);
			}
			return requiredBytes;
		}

		@Override
		public final void reset() {
			digest = null;// TODO // new MD5();
			// nonceSize = 1/2 security_strength
			nonce = new byte[size];
			Truerandomness source = Truerandomness.shared(TRNG.NATIVE);
			source.read(nonce);
			counter = source.nextInt();
		}

		@Override
		public final String toString() {
			return "RBG.NONCE";
		}

		@Override
		public final void close() {
			nonce = null;
			digest = null;
		}

		@Override
		public final boolean isOpen() {
			return nonce != null;
		}

		@Override
		public final int minlen() {
			return size;
		}

		@Override
		public int tryRead(ByteBuffer buffer) {
			throw new UnsupportedOperationException();
		}
	}

}
