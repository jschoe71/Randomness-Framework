package org.randomness;

import java.nio.ByteBuffer;
import java.nio.DoubleBuffer;
import java.nio.FloatBuffer;
import java.nio.IntBuffer;
import java.nio.LongBuffer;
import java.nio.channels.NonReadableChannelException;
import java.util.ConcurrentModificationException;

final class PseudorandomnessThreadLocal extends Pseudorandomness {
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	/**
	 * Lock to prevent concurrent modification of the RNG's internal state
	 */
	final PseudorandomnessEngine engine;
	private final Thread parent;
	private final boolean precision64;

	public PseudorandomnessThreadLocal(PseudorandomnessEngine engine,
			Thread thread) {
		this.engine = engine;
		this.parent = thread;
		precision64 = (engine.minlen() == LONG_SIZE_BYTES);
	}

	// //////////////////////////////////////////////////////
	// ///////////// PRNG FUNCTIONS /////////////////////////
	// //////////////////////////////////////////////////////

	@Override
	public final void reset() {
		if (parent != Thread.currentThread())
			throw new ConcurrentModificationException(
					"Attempt to modify thread local instance from another thread");

		nextInt = nextLong = true; // clear intermediate state
		engine.reset();
	}

	@Override
	public final Pseudorandomness reseed(ByteBuffer seed) {
		if (parent != Thread.currentThread())
			throw new ConcurrentModificationException(
					"Attempt to modify thread local instance from another thread");

		nextInt = nextLong = true; // clear intermediate state
		engine.reseed(seed);

		return this;
	}

	@Override
	public final boolean isOpen() {
		return engine.isOpen();
	}

	@Override
	public final void close() {
		if (parent != Thread.currentThread())
			throw new ConcurrentModificationException(
					"Attempt to modify thread local instance from another thread");

		nextInt = nextLong = true; // clear intermediate state
		engine.close();
	}

	@Override
	public final int minlen() {
		return engine.minlen();
	}

	@Override
	protected final int seedlen() {
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

	// //////////////////////////////////////////////////////
	// ///////////// PRNG GENERATE FUNCTIONS ////////////////
	// //////////////////////////////////////////////////////

	@Override
	public final int read(ByteBuffer buffer) {
		if (parent != Thread.currentThread())
			throw new ConcurrentModificationException(
					"Attempt to modify thread local instance from another thread");

		if (!engine.isOpen())
			throw new NonReadableChannelException();

		nextInt = nextLong = true; // clear intermediate state
		return engine.read(buffer);

	}

	@Override
	public final int read(DoubleBuffer doubleBuffer) {
		if (parent != Thread.currentThread())
			throw new ConcurrentModificationException(
					"Attempt to modify thread local instance from another thread");

		if (!engine.isOpen())
			throw new NonReadableChannelException();

		nextInt = nextLong = true; // clear intermediate state
		return engine.read(doubleBuffer);

	}

	@Override
	public int tryRead(ByteBuffer buffer) {
		if (parent != Thread.currentThread())
			throw new ConcurrentModificationException(
					"Attempt to modify thread local instance from another thread");

		if (!engine.isOpen())
			throw new NonReadableChannelException();

		nextInt = nextLong = true; // clear intermediate state
		return engine.tryRead(buffer);
	}

	@Override
	public final int read(IntBuffer intBuffer) {
		if (parent != Thread.currentThread())
			throw new ConcurrentModificationException(
					"Attempt to modify thread local instance from another thread");

		if (!engine.isOpen())
			throw new NonReadableChannelException();

		nextInt = nextLong = true; // clear intermediate state
		return engine.read(intBuffer);
	}

	@Override
	public int read(FloatBuffer floatBuffer) {
		if (parent != Thread.currentThread())
			throw new ConcurrentModificationException(
					"Attempt to modify thread local instance from another thread");

		if (!engine.isOpen())
			throw new NonReadableChannelException();

		nextInt = nextLong = true; // clear intermediate state
		return engine.read(floatBuffer);
	}

	@Override
	public final int read(LongBuffer longBuffer) {
		if (parent != Thread.currentThread())
			throw new ConcurrentModificationException(
					"Attempt to modify thread local instance from another thread");

		if (!engine.isOpen())
			throw new NonReadableChannelException();

		nextInt = nextLong = true; // clear intermediate state
		return engine.read(longBuffer);
	}

	@Override
	public final Pseudorandomness copy() {
		if (parent != Thread.currentThread())
			throw new ConcurrentModificationException(
					"Attempt to modify thread local instance from another thread");

		if (!engine.isOpen())
			throw new NonReadableChannelException();

		PseudorandomnessEngine copyEngine = (PseudorandomnessEngine) engine
				.copy();

		PseudorandomnessThreadLocal copy = new PseudorandomnessThreadLocal(
				copyEngine, parent);

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
	public final boolean nextBoolean() {
		if (parent != Thread.currentThread())
			throw new ConcurrentModificationException(
					"Attempt to modify thread local instance from another thread");

		if (!engine.isOpen())
			throw new NonReadableChannelException();

		if (mask8 == 1 || (nextInt || nextLong || nextByte || nextShort)) {
			word8 = nextByte();
			mask8 = 256;
			nextByte = nextShort = nextInt = nextLong = false;
		}

		return (word8 & (mask8 >>>= 1)) != 0;
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
	public final byte nextByte() {
		if (parent != Thread.currentThread())
			throw new ConcurrentModificationException(
					"Attempt to modify thread local instance from another thread");

		if (!engine.isOpen())
			throw new NonReadableChannelException();

		nextByte = true;

		if (nextInt || newByte || nextLong || nextShort) {
			word16 = nextShort();
			newByte = false;
			nextShort = nextInt = nextLong = false;
			return (byte) (word16 >>> 8); // high 8
		}

		newByte = true; // need new word16 at next cycle.

		return (byte) word16; // low 8;

	}

	@Override
	public final short nextShort() {
		if (parent != Thread.currentThread())
			throw new ConcurrentModificationException(
					"Attempt to modify thread local instance from another thread");

		if (!engine.isOpen())
			throw new NonReadableChannelException();

		nextShort = true;

		if (nextInt || newShort || nextLong) {
			word32 = nextInt();
			newShort = false;
			nextInt = nextLong = false;
			return (short) (word32 >>> 16); // high 16
		}

		newShort = true; // need new word32 at next cycle.

		return (short) (word32); // low 16;
	}

	@Override
	public final int nextInt() {
		if (parent != Thread.currentThread())
			throw new ConcurrentModificationException(
					"Attempt to modify thread local instance from another thread");

		if (!engine.isOpen())
			throw new NonReadableChannelException();

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
	}

	@Override
	public final long nextLong() {
		if (parent != Thread.currentThread())
			throw new ConcurrentModificationException(
					"Attempt to modify thread local instance from another thread");

		if (!engine.isOpen())
			throw new NonReadableChannelException();

		nextLong = true;
		return engine.nextLong();
	}

	@Override
	public final double nextDouble() {
		if (parent != Thread.currentThread())
			throw new ConcurrentModificationException(
					"Attempt to modify thread local instance from another thread");

		if (!engine.isOpen())
			throw new NonReadableChannelException();

		nextLong = true;
		return engine.nextDouble();
	}

	@Override
	public final float nextFloat() {
		if (parent != Thread.currentThread())
			throw new ConcurrentModificationException(
					"Attempt to modify thread local instance from another thread");

		if (!engine.isOpen())
			throw new NonReadableChannelException();

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
			return ((((int) (word64)) >>> 8) / ((float) (1 << 24))); // low 32
		}

		return engine.nextFloat();

	}

}
