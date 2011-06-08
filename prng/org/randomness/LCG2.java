/**
 * 
 */
package org.randomness;

import java.nio.ByteBuffer;
import java.nio.DoubleBuffer;
import java.nio.FloatBuffer;
import java.nio.IntBuffer;
import java.nio.LongBuffer;
import java.nio.channels.NonReadableChannelException;
import java.util.Random;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Wrapper over {@linkplain Random java.util.Random} class.
 * 
 * @author Anton Kabysh
 * 
 */
final class LCG2 extends PseudorandomnessEngine implements Engine.LCG64 {

	/** use serialVersionUID from JDK 1.1 for interoperability */
	static final long serialVersionUID = 3905348978240129619L;

	/**
	 * The internal state associated with this pseudorandom number generator.
	 * (The specs for the methods in this class describe the ongoing computation
	 * of this value.)
	 * 
	 * @serial
	 */
	private long seed;

	private final static long multiplier = 0x5DEECE66DL;
	private final static long addend = 0xBL;
	private final static long mask = (1L << 48) - 1;

	public LCG2() {
		this.reset();
	}

	public long seed() {
		return seed;
	}

	@Override
	public final String toString() {
		return PRNG.LCG.name();
	}

	@Override
	protected final void instantiate(ByteBuffer seed) {

		long seedValue = seed.getLong();

		this.seed = (seedValue ^ multiplier) & mask;

	}

	private int generate32() {
		return (int) ((this.seed = ((this.seed * multiplier + addend) & mask)) >>> 16);
	}

	@Override
	public final int read(byte[] bytes) {
		int i = 0;
		final int iEnd = bytes.length - 3;
		while (i < iEnd) {
			final int random = generate32();
			bytes[i] = (byte) (random & 0xff);
			bytes[i + 1] = (byte) ((random >> 8) & 0xff);
			bytes[i + 2] = (byte) ((random >> 16) & 0xff);
			bytes[i + 3] = (byte) ((random >> 24) & 0xff);
			i += 4;
		}

		int random = generate32();
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

			buffer.putInt((int) ((this.seed = ((this.seed * multiplier + addend) & mask)) >>> 16));
			bytes += INT_SIZE_BYTES; // inc bytes

		}

		if (bytes < numBytes) {
			// put last bytes
			int rnd = generate32();

			for (int n = numBytes - bytes; n-- > 0; bytes++)
				buffer.put((byte) (rnd >>> (Byte.SIZE * n)));
		}

		return numBytes - buffer.remaining();
	}

	@Override
	public final int read(IntBuffer intBuffer) {

		final int numInts = intBuffer.remaining();

		int ints = 0;

		for (; ints < numInts;) {

			intBuffer
					.put((int) ((this.seed = ((this.seed * multiplier + addend) & mask)) >>> 16));
			ints++;
		}

		return numInts - intBuffer.remaining();
	}

	@Override
	public int read(FloatBuffer floatBuffer) {
		final int numFloats = floatBuffer.remaining();

		int floats = 0;

		for (; floats < numFloats; floats++) {

			int y = (int) ((this.seed = ((this.seed * multiplier + addend) & mask)) >>> 16);
			floatBuffer.put((y >>> 8) / ((float) (1 << 24)));
		}

		return numFloats - floatBuffer.remaining();
	}

	@Override
	public final int read(LongBuffer longBuffer) {
		final int numLongs = longBuffer.remaining();

		for (int longs = 0; longs < numLongs;) {

			seed = ((this.seed * multiplier + addend) & mask);
			int l = (int) (seed >>> 16);

			seed = ((this.seed * multiplier + addend) & mask);
			int r = (int) (seed >>> 16);

			longBuffer.put((((long) l) << 32) + r);
			longs++;
		}

		return numLongs - longBuffer.remaining();
	}

	@Override
	public final int read(DoubleBuffer doubleBuffer) {

		final int numDoubles = doubleBuffer.remaining();
		int doubles = 0;

		for (; doubles < numDoubles; doubles++) {

			seed = ((this.seed * multiplier + addend) & mask);
			int l = (int) (seed >>> 16);

			seed = ((this.seed * multiplier + addend) & mask);
			int r = (int) (seed >>> 16);

			doubleBuffer.put(((((long) (l >>> 6)) << 27) + (r >>> 5))
					/ (double) (1L << 53));
		}

		return numDoubles - doubleBuffer.remaining() /* should be zero */;

	}

	@Override
	public final int nextInt() {
		return (int) ((this.seed = ((this.seed * multiplier + addend) & mask)) >>> 16);
	}

	@Override
	public float nextFloat() {

		int y = (int) ((this.seed = ((this.seed * multiplier + addend) & mask)) >>> 16);

		return ((y >>> 8) / ((float) (1 << 24)));
	}

	@Override
	public final long nextLong() {
		long newseed = ((this.seed * multiplier + addend) & mask);
		int l = (int) (newseed >>> 16);

		newseed = ((newseed * multiplier + addend) & mask);
		int r = (int) (newseed >>> 16);
		this.seed = newseed;
		return (((long) l) << 32) + r;
	}

	@Override
	public double nextDouble() {
		seed = ((this.seed * multiplier + addend) & mask);
		int l = (int) (seed >>> 16);

		seed = ((this.seed * multiplier + addend) & mask);
		int r = (int) (seed >>> 16);
		return ((((long) (l >>> 6)) << 27) + (r >>> 5)) / (double) (1L << 53);
	}

	@Override
	public final int hashCode() {
		if (!isOpen())
			return System.identityHashCode(this);

		int hash = 17;
		long value = seed();
		return hash * 31 + (int) (value ^ (value >>> 32));
	}

	@Override
	public final boolean equals(Object obj) {
		if (obj == null)
			return false;

		if (!this.isOpen())
			return false;

		if (obj == this)
			return true;

		if (!(obj instanceof Pseudorandomness))
			return false;

		if (!(obj instanceof Engine.LCG64))
			return false;

		Pseudorandomness that = (Pseudorandomness) obj;
		Engine.LCG64 engine = (Engine.LCG64) obj;

		if (this.isOpen() && that.isOpen())
			return engine.seed() == this.seed();

		return false;
	}

	@Override
	public final LCG2 copy() {
		LCG2 copy = new LCG2();
		copy.reseed((ByteBuffer) this.mark.clear());
		copy.seed = this.seed;

		return copy;
	}

	@Override
	public final int minlen() {
		return INT_SIZE_BYTES;
	}

	final static class Shared extends PseudorandomnessEngine implements
			Engine.LCG64 {

		/**
		 * 
		 */
		private static final long serialVersionUID = 1L;
		/**
		 * The internal state associated with this pseudorandom number
		 * generator. (The specs for the methods in this class describe the
		 * ongoing computation of this value.)
		 * 
		 * @serial
		 */
		private final AtomicLong seed = new AtomicLong(0L);

		private final ReentrantLock lock = new ReentrantLock();

		public Shared() {
			this.reset();
		}

		@Override
		public final String toString() {
			return PRNG.LCG.name();
		}

		public long seed() {
			return seed.get();
		}

		@Override
		protected final void instantiate(ByteBuffer seed) {

			long seedValue = seed.getLong();

			seedValue = (seedValue ^ multiplier) & mask;
			this.seed.set(seedValue);

			nextInt = nextLong = true; // clear intermediate state

		}

		private final long acquireSeed() {
			return seed.get();
			// // wait until counter is released.
			// long lcg;
			// AtomicLong seed = this.seed;
			//
			// for (;;) {
			// lcg = seed.get();
			//
			// // possibly in generate function
			// if (lcg != -1) {
			// if (seed.compareAndSet(lcg, -1)) // lock
			// return lcg;
			// }
			// }
		}

		@Override
		public final int read(byte[] bytes) {
			if (!isOpen())
				throw new NonReadableChannelException();

			try {
				lock.lock();
				nextInt = nextLong = true; // clear intermediate state
				long oldseed = acquireSeed(), nextseed = 0;

				int i = 0;
				final int iEnd = bytes.length - 3;

				while (i < iEnd) {

					if (!isOpen()) // check interruption status
						return i;

					nextseed = (oldseed * multiplier + addend) & mask;
					oldseed = nextseed;
					final int random = (int) (nextseed >>> 16);
					bytes[i] = (byte) (random & 0xff);
					bytes[i + 1] = (byte) ((random >> 8) & 0xff);
					bytes[i + 2] = (byte) ((random >> 16) & 0xff);
					bytes[i + 3] = (byte) ((random >> 24) & 0xff);
					i += 4;
				}

				nextseed = (oldseed * multiplier + addend) & mask;
				oldseed = nextseed;
				int random = (int) (nextseed >>> 16);

				while (i < bytes.length) {
					bytes[i++] = (byte) (random & 0xff);
					random = random >> 8;
				}

				seed.set(nextseed);
			} finally {
				lock.unlock();
			}

			return bytes.length;
		}

		@Override
		public final int read(ByteBuffer buffer) {
			if (!isOpen())
				throw new NonReadableChannelException();

			final int numBytes = buffer.remaining();

			try {
				lock.lock();
				nextInt = nextLong = true; // clear intermediate state
				long oldseed = acquireSeed(), nextseed = 0;
				int bytes = 0;

				for (; (numBytes - bytes) >= INT_SIZE_BYTES;) {

					if (!isOpen()) // check interruption status
						return bytes; // interrupt

					nextseed = (oldseed * multiplier + addend) & mask;
					oldseed = nextseed;
					buffer.putInt((int) (nextseed >>> (16)));
					bytes += INT_SIZE_BYTES; // inc bytes
				}

				assert seed.get() == -1;

				if (bytes < numBytes) {
					// put last bytes
					nextseed = (oldseed * multiplier + addend) & mask;
					int rnd = (int) (nextseed >>> (16));

					for (int n = numBytes - bytes; n-- > 0; bytes++)
						buffer.put((byte) (rnd >>> (Byte.SIZE * n)));
				}

				seed.set(nextseed);
			} finally {
				lock.unlock();
			}

			return numBytes - buffer.remaining();
		}

		@Override
		public final int read(IntBuffer intBuffer) {
			if (!isOpen())
				throw new NonReadableChannelException();

			final int numInts = intBuffer.remaining();
			int ints = 0;

			try {
				lock.lock();
				nextInt = nextLong = true; // clear intermediate state
				long oldseed = acquireSeed(), nextseed = 0;

				for (; ints < numInts;) {

					if (!isOpen()) // check interruption status
						return ints; // interrupt

					nextseed = (oldseed * multiplier + addend) & mask;
					oldseed = nextseed;
					intBuffer.put((int) (nextseed >>> (16)));
					ints++;
				}

				assert seed.get() == -1;

				seed.set(nextseed);
			} finally {
				lock.unlock();
			}

			return numInts - intBuffer.remaining();
		}

		@Override
		public int read(FloatBuffer floatBuffer) {
			if (!isOpen())
				throw new NonReadableChannelException();

			final int numFloats = floatBuffer.remaining();

			try {
				lock.lock();
				nextInt = nextLong = true; // clear intermediate state
				long oldseed = acquireSeed(), nextseed = 0;

				for (int floats = 0; floats < numFloats; floats++) {

					if (!isOpen()) // check interruption status
						return floats; // interrupt

					nextseed = (oldseed * multiplier + addend) & mask;
					oldseed = nextseed;
					floatBuffer.put((((int) (nextseed >>> (16))) >>> 8)
							/ ((float) (1 << 24)));
				}

				assert seed.get() == -1;
				seed.set(nextseed);

			} finally {
				lock.unlock();
			}

			return numFloats - floatBuffer.remaining();
		}

		@Override
		public final int read(LongBuffer longBuffer) {
			if (!isOpen())
				throw new NonReadableChannelException();

			final int numLongs = longBuffer.remaining();

			try {
				lock.lock();
				nextInt = nextLong = true; // clear intermediate state
				long oldseed = acquireSeed(), nextseed = 0;

				for (int longs = 0; longs < numLongs; longs++) {

					if (!isOpen()) // check interruption status
						return longs; // interrupt

					nextseed = (oldseed * multiplier + addend) & mask;
					int l = (int) (nextseed >>> (16));

					nextseed = (nextseed * multiplier + addend) & mask;
					int r = (int) (nextseed >>> (16));

					oldseed = nextseed;

					longBuffer.put((((long) l) << 32) + r);

				}

				assert seed.get() == -1;
				seed.set(nextseed);

			} finally {
				lock.unlock();
			}

			return numLongs - longBuffer.remaining();
		}

		@Override
		public final int read(DoubleBuffer doubleBuffer) {
			if (!isOpen())
				throw new NonReadableChannelException();

			final int numDoubles = doubleBuffer.remaining();
			try {
				lock.lock();
				nextInt = nextLong = true; // clear intermediate state
				long oldseed = acquireSeed(), nextseed = 0;

				for (int doubles = 0; doubles < numDoubles; doubles++) {

					if (!isOpen()) // check interruption status
						return doubles; // interrupt

					nextseed = (oldseed * multiplier + addend) & mask;
					int l = (int) (nextseed >>> (16));

					nextseed = (nextseed * multiplier + addend) & mask;
					int r = (int) (nextseed >>> (16));

					oldseed = nextseed;

					doubleBuffer.put(((((long) (l >>> 6)) << 27) + (r >>> 5))
							/ (double) (1L << 53));
				}
				assert seed.get() == -1;
				seed.set(nextseed);

			} finally {
				lock.unlock();
			}
			return numDoubles - doubleBuffer.remaining() /* should be zero */;

		}

		private int mask8 = 1;

		// //////////////// INTERMEDIATE STATE/// ////////////////////
		private volatile byte word8; // eight bits
		private volatile short word16;; // two bytes
		private volatile int word32; // two shorts

		private volatile boolean newByte = true; // we need new byte?
		private volatile boolean newShort = true; // we need new short?

		private volatile boolean nextByte = true; // generated next byte?
		private volatile boolean nextShort = true; // generated next short?
		private volatile boolean nextInt = true; // generated next int?
		private volatile boolean nextLong = true;// generated next long?

		@Override
		public final boolean nextBoolean() {
			if (!isOpen())
				throw new NonReadableChannelException();

			if (mask8 == 1 || (nextInt || nextLong || nextByte || nextShort)) {
				word8 = nextByte();
				mask8 = 256;
				nextByte = nextShort = nextInt = nextLong = false;
			}

			return (word8 & (mask8 >>>= 1)) != 0;
		}

		@Override
		public byte nextByte() {
			if (!isOpen())
				throw new NonReadableChannelException();

			nextByte = true;

			if ((nextInt || nextLong || nextShort) || newByte) {
				word16 = nextShort();
				newByte = false;
				nextShort = nextInt = nextLong = false;
				return (byte) (word16 >>> 8); // high 8
			}

			newByte = true; // need new word16 at next cycle.
			return (byte) word16; // low 8;
		}

		@Override
		public short nextShort() {
			if (!isOpen())
				throw new NonReadableChannelException();

			nextShort = true;

			if ((nextInt || nextLong) || newShort) {
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
			if (!isOpen())
				throw new NonReadableChannelException();

			while (lock.isLocked()) {
				continue;
			}

			nextInt = true;

			long oldseed, nextseed;
			AtomicLong seed = this.seed;
			do {
				oldseed = seed.get();
				nextseed = (oldseed * multiplier + addend) & mask;
			} while (!seed.compareAndSet(oldseed, nextseed));
			return (int) (nextseed >>> (16));

		}

		@Override
		public float nextFloat() {
			if (!isOpen())
				throw new NonReadableChannelException();

			while (lock.isLocked()) {
				continue;
			}

			nextInt = true;

			long oldseed, nextseed;
			AtomicLong seed = this.seed;
			do {
				oldseed = seed.get();
				nextseed = (oldseed * multiplier + addend) & mask;
			} while (!seed.compareAndSet(oldseed, nextseed));

			return ((((int) (nextseed >>> (16))) >>> 8) / ((float) (1 << 24)));
		}

		@Override
		public final long nextLong() {
			if (!isOpen())
				throw new NonReadableChannelException();

			while (lock.isLocked()) {
				continue;
			}
			nextLong = true;

			int l;
			int r;
			{
				long oldseed, nextseed;
				AtomicLong seed = this.seed;
				do { // atomic
					oldseed = seed.get();
					nextseed = (oldseed * multiplier + addend) & mask;
					l = (int) (nextseed >>> (16));

					nextseed = (nextseed * multiplier + addend) & mask;
					r = (int) (nextseed >>> (16));

				} while (!seed.compareAndSet(oldseed, nextseed));

			}

			return (((long) l) << 32) + r;
		}

		@Override
		public double nextDouble() {
			if (!isOpen())
				throw new NonReadableChannelException();

			while (lock.isLocked()) {
				continue;
			}
			nextLong = true;

			int l;
			int r;

			{
				long oldseed, nextseed;
				AtomicLong seed = this.seed;
				do { // atomic
					oldseed = seed.get();
					nextseed = (oldseed * multiplier + addend) & mask;
					l = (int) (nextseed >>> (16));

					nextseed = (nextseed * multiplier + addend) & mask;
					r = (int) (nextseed >>> (16));

				} while (!seed.compareAndSet(oldseed, nextseed));

			}

			return ((((long) (l >>> 6)) << 27) + (r >>> 5))
					/ (double) (1L << 53);

		}

		@Override
		public final int hashCode() {
			if (!isOpen())
				return System.identityHashCode(this);

			int hash = 17;
			long value = seed();
			return hash * 31 + (int) (value ^ (value >>> 32));
		}

		@Override
		public final boolean equals(Object obj) {

			if (obj == null)
				return false;

			if (!this.isOpen())
				return false;

			if (obj instanceof PseudorandomnessSharedLock) {
				obj = ((PseudorandomnessSharedLock) obj).engine;
			}
			if (obj instanceof PseudorandomnessThreadLocal) {
				obj = ((PseudorandomnessThreadLocal) obj).engine;
			}

			if (obj == this)
				return true;

			if (!(obj instanceof Pseudorandomness))
				return false;

			if (!(obj instanceof Engine.LCG64))
				return false;

			Pseudorandomness that = (Pseudorandomness) obj;
			Engine.LCG64 engine = (Engine.LCG64) obj;

			if (this.isOpen() && that.isOpen())
				return engine.seed() == this.seed();

			return false;
		}

		@Override
		public final LCG2.Shared copy() {
			if (!isOpen())
				throw new NonReadableChannelException();

			try {
				lock.lock();

				LCG2.Shared shared = new Shared();
				shared.reseed((ByteBuffer) this.mark.clear());
				shared.seed.set(this.seed.get());

				{ // copy intermediate state
					shared.nextByte = this.nextByte;
					shared.nextShort = this.nextShort;
					shared.nextInt = this.nextInt;
					shared.nextLong = this.nextLong;

					shared.newByte = this.newByte;
					shared.newShort = this.newShort;

					shared.mask8 = this.mask8;

					shared.word8 = this.word8;
					shared.word16 = this.word16;
					shared.word32 = this.word32;
				}

				return shared;
			} finally {
				lock.unlock();
			}

		}

		@Override
		public final int minlen() {
			return INT_SIZE_BYTES;
		}

	}
}