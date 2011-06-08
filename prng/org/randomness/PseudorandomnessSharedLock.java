package org.randomness;

import java.nio.ByteBuffer;
import java.nio.DoubleBuffer;
import java.nio.FloatBuffer;
import java.nio.IntBuffer;
import java.nio.LongBuffer;
import java.nio.channels.NonReadableChannelException;
import java.util.concurrent.locks.ReentrantLock;

final class PseudorandomnessSharedLock extends Pseudorandomness {
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	/**
	 * Lock to prevent concurrent modification of the RNG's internal state
	 */
	private final ReentrantLock lock;
	private final boolean precision64;
	final PseudorandomnessEngine engine;

	public PseudorandomnessSharedLock(PseudorandomnessEngine engine) {
		this.engine = engine;
		this.lock = new ReentrantLock();
		precision64 = (engine.minlen() == LONG_SIZE_BYTES);
	}

	// ///////////////////////////////////////////////////////////
	// /////////////// PRNG MECHANISMS ///////////////////////////
	// ///////////////////////////////////////////////////////////

	@Override
	public final void reset() {
		try {
			lock.lock();

			nextInt = nextLong = true; // clear intermediate state
			engine.reset();

		} finally {
			lock.unlock();
		}
	}

	@Override
	public final Pseudorandomness reseed(ByteBuffer seed) {
		try {
			lock.lock();

			nextInt = nextLong = true; // clear intermediate state
			engine.reseed(seed);

		} finally {
			lock.unlock();
		}

		return this;
	}

	@Override
	public final int tryRead(ByteBuffer buffer) {
		if (lock.isLocked())
			return -1;

		return this.read(buffer);
	}

	@Override
	public final boolean isOpen() {
		return engine.isOpen();
	}

	@Override
	public final void close() {
		engine.close();
	}

	@Override
	public final int minlen() {
		return engine.minlen();
	}

	@Override
	protected int seedlen() {
		return engine.seedlen();
	}

	@Override
	protected final ByteBuffer newBuffer(int bufferSize) {
		return engine.newBuffer(bufferSize);
	}

	@Override
	protected final byte[] getEntropyInput(int minEntropy) {
		return engine.getEntropyInput(minEntropy);
	}

	// ///////////////////////////////////////////////////////////
	// /////////////// PRNG GENERATE FUNCTIONS ///////////////////
	// ///////////////////////////////////////////////////////////

	@Override
	public final int read(ByteBuffer buffer) {
		if (!engine.isOpen())
			throw new NonReadableChannelException();

		try {
			lock.lock();

			nextInt = nextLong = true; // clear intermediate state
			return engine.read(buffer);

		} finally {
			lock.unlock();
		}
	}

	@Override
	public final int read(DoubleBuffer doubleBuffer) {
		if (!engine.isOpen())
			throw new NonReadableChannelException();

		try {
			lock.lock();

			nextInt = nextLong = true; // clear intermediate state
			return engine.read(doubleBuffer);

		} finally {
			lock.unlock();
		}
	}

	@Override
	public final int read(IntBuffer intBuffer) {
		if (!engine.isOpen())
			throw new NonReadableChannelException();

		try {
			lock.lock();

			nextInt = nextLong = true; // clear intermediate state
			return engine.read(intBuffer);

		} finally {
			lock.unlock();
		}
	}

	@Override
	public final int read(FloatBuffer floatBuffer) {
		if (!engine.isOpen())
			throw new NonReadableChannelException();

		try {
			lock.lock();

			nextInt = nextLong = true; // clear intermediate state
			return engine.read(floatBuffer);

		} finally {
			lock.unlock();
		}
	}

	@Override
	public final int read(LongBuffer longBuffer) {
		if (!engine.isOpen())
			throw new NonReadableChannelException();

		try {
			lock.lock();

			nextInt = nextLong = true; // clear intermediate state
			return engine.read(longBuffer);

		} finally {
			lock.unlock();
		}
	}

	@Override
	public final int hashCode() {
		if (!engine.isOpen())
			return System.identityHashCode(engine);

		return engine.hashCode();
	}

	@Override
	public final boolean equals(Object obj) {
		if (obj instanceof PseudorandomnessSharedLock) {
			obj = ((PseudorandomnessSharedLock) obj).engine;
		}
		if (obj instanceof PseudorandomnessThreadLocal) {
			obj = ((PseudorandomnessThreadLocal) obj).engine;
		}

		return engine.equals(obj);
	}

	@Override
	public final String toString() {
		return engine.toString();
	}

	@Override
	public final Pseudorandomness copy() {
		if (!engine.isOpen())
			throw new NonReadableChannelException();

		try {
			lock.lock();

			PseudorandomnessSharedLock copy = new PseudorandomnessSharedLock(
					(PseudorandomnessEngine) engine.copy());

			{ // copy intermediate state
				copy.nextByte = this.nextByte;
				copy.nextShort = this.nextShort;
				copy.nextInt = this.nextInt;
				copy.nextLong = this.nextLong;

				copy.newByte = this.newByte;
				copy.newShort = this.newShort;
				copy.newInt = this.newInt;

				copy.mask8 = this.mask8;

				copy.word8 = this.word8;
				copy.word16 = this.word16;
				copy.word32 = this.word32;
				copy.word64 = this.word64;
			}

			return copy;

		} finally {
			lock.unlock();
		}
	}

	private int mask8 = 1;

	// //////////////// INTERMEDIATE STATE/// ////////////////////
	private byte word8; // eight bits
	private short word16;; // two bytes
	private int word32; // two shorts
	private long word64; // two int's

	private boolean newByte = true; // we need new byte?
	private boolean newShort = true; // we need new short?
	private boolean newInt = true; // we need new int?

	private boolean nextByte = true; // generated next byte?
	private boolean nextShort = true; // generated next short?
	private boolean nextInt = true; // generated next int?
	private boolean nextLong = true;// generated next long?

	@Override
	public final boolean nextBoolean() {
		if (!engine.isOpen())
			throw new NonReadableChannelException();

		try {
			lock.lock();

			if (mask8 == 1 || (nextInt || nextLong || nextByte || nextShort)) {
				word8 = nextByte();
				mask8 = 256;
				nextByte = nextShort = nextInt = nextLong = false;
			}

			return (word8 & (mask8 >>>= 1)) != 0;

		} finally {
			lock.unlock();
		}
	}

	@Override
	public final byte nextByte() {
		if (!engine.isOpen())
			throw new NonReadableChannelException();

		try {
			lock.lock();

			nextByte = true;

			if (nextInt || newByte || nextLong || nextShort) {
				word16 = nextShort();
				newByte = false;
				nextShort = nextInt = nextLong = false;
				return (byte) (word16 >>> 8); // high 8
			}

			newByte = true; // need new word16 at next cycle.

			return (byte) word16; // low 8;

		} finally {
			lock.unlock();
		}
	}

	@Override
	public final short nextShort() {
		if (!engine.isOpen())
			throw new NonReadableChannelException();

		try {
			lock.lock();

			nextShort = true;

			if (nextInt || newShort || nextLong) {
				word32 = nextInt();
				newShort = false;
				nextInt = nextLong = false;
				return (short) (word32 >>> 16); // high 16
			}

			newShort = true; // need new word32 at next cycle.

			return (short) (word32); // low 16;

		} finally {
			lock.unlock();
		}
	}

	@Override
	public final int nextInt() {
		if (!engine.isOpen())
			throw new NonReadableChannelException();

		try {
			lock.lock();

			nextInt = true;

			if (precision64) { // for 64 bit precision generators.

				if (nextLong || newInt) {
					word64 = nextLong();
					newInt = false;
					nextLong = false;
					return (int) (word64 >>> 32); // high 32
				}

				newInt = true;
				return (int) (word64); // low 32;
			}

			return engine.nextInt();

		} finally {
			lock.unlock();
		}
	}

	@Override
	public final long nextLong() {
		if (!engine.isOpen())
			throw new NonReadableChannelException();

		try {
			lock.lock();

			nextLong = true;
			return engine.nextLong();

		} finally {
			lock.unlock();
		}
	}

	@Override
	public final double nextDouble() {
		if (!engine.isOpen())
			throw new NonReadableChannelException();

		try {
			lock.lock();

			nextLong = true;
			return engine.nextDouble();

		} finally {
			lock.unlock();
		}
	}

	@Override
	public final float nextFloat() {
		if (!engine.isOpen())
			throw new NonReadableChannelException();

		try {
			lock.lock();

			nextInt = true;

			if (precision64) { // for 64 bit precision generators.

				if (nextLong || newInt) {
					word64 = nextLong();
					newInt = false;
					nextLong = false;

					return ((((int) (word64 >>> 32)) >>> 8) / ((float) (1 << 24))); // high
																					// 32
				}

				newInt = true;
				return ((((int) (word64)) >>> 8) / ((float) (1 << 24))); // low
																			// 32
			}

			return engine.nextFloat();

		} finally {
			lock.unlock();
		}
	}

}
