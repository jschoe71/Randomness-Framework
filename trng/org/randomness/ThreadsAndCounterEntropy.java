package org.randomness;

import java.nio.ByteBuffer;
import java.nio.channels.NonReadableChannelException;

/**
 * Generate entropy using Thread synchronization and counter to generate random
 * bytes, its following the same sort of strategy as the
 * {@linkplain TRNG#THREADS_SYNCHRONIZATION thread synchronization}, but not so
 * expensive in terms of CPU time and always generates new entropy each time.
 * <p>
 * This type of entropy is very time dependent. This is not provably real
 * entropy, but plausibly so this can be used as an explicit entropy source.
 * This is not a good substitute for real external entropy, e.g.
 * {@linkplain TRNG#RANDOM_ORG random.org} or {@linkplain TRNG#HOTBITS hotbits}.
 * <p>
 * This may not work with all VMs but attempts to adapt itself to the current VM
 * and workload to be as robust (and fast) as possible.
 * <p>
 * 
 * @author Anton Kabysh (randomness adaptation)
 * @author Damon Hart-Davis. (<code>Entropy Pool</code> version)
 * @author The main idea of the algorithm is based on an idea of Marcus Lippert.
 */
class ThreadsAndCounterEntropy extends TruerandomnessEngine {
	/**
	 * Minimum time spent on gathering each bit (ms). Ideally this should be
	 * prime ish to help avoid collisions with other regular activity in the
	 * JVM.
	 * <p>
	 * If we make this smaller then we can potentially gather entropy faster on
	 * faster JVMs/CPUs, but there might not actually be entropy to be gathered!
	 * <p>
	 * This should probably be in the region of 1ms--50ms.
	 */
	static final int MIN_MS_PER_BIT = 3;

	/**
	 * Minimum count cycles to gather one bit. This must be sufficiently large
	 * that the least-significant bit in the counter must be relatively
	 * unpredictable.
	 * <p>
	 * The larger this is the better the entropy gathered, probably. (Note that
	 * on a Solaris 8 host, the thread can give up its timeslice to a thread in
	 * another more-niced process on Thread.yield(), making this run very slowly
	 * indeed.)
	 * <p>
	 * Should probably be at least in the hundreds, but may be prohibitively
	 * expensive. Down in the tens we begin to risk skewed results.
	 * <p>
	 * A prime-ish number is probably a good thing.
	 */
	static final int MIN_COUNTS_PER_BIT = 59;

	@Override
	public int read(ByteBuffer buffer) {

		final CounterThread cth = new CounterThread();

		try {
			cth.start();
			final int requiredBytes = buffer.remaining();

			// Now fill in the return array byte-by-byte.
			for (int i = requiredBytes; --i >= 0;) {
				// The value of the result byte that we are computing.
				byte thisByte = 0;

				// Now fill in the target result byte value bit-by-bit.
				for (int b = 8; --b >= 0;) {
					// Sample the count before gathering this entropy bit.
					final int initialCount = cth.counter;

					// Pause longer and longer
					// (back off exponentially)
					// until we've at least counted a biggish chunk.
					// We've waited at least MIN_MS_PER_BIT at this stage too.
					int sample_ms;
					for (sample_ms = MIN_MS_PER_BIT; cth.counter - initialCount < MIN_COUNTS_PER_BIT; sample_ms = (sample_ms * 2) + 1) {
						// Let the counter cycle in the background...
						try {
							Thread.sleep(sample_ms);
						} catch (InterruptedException e) {
						}
					}
					// Now sleep again to ensure that we will not know count.
					// This should be about as long as we slept in total
					// before and should thus mean that the counter should
					// have a chance to increment about MIN_COUNTS_PER_BIT
					// again without interruption by us.
					try {
						Thread.sleep(sample_ms);
					} catch (InterruptedException e) {
					}

					thisByte <<= 1;
					// Capture the least-significant counter bit as noise.
					thisByte ^= (cth.counter & 1);
				}

				buffer.put(thisByte);
			}
			return requiredBytes;
		} finally {
			// Ask the counter thread to quit...
			cth.pleaseStop = true;
			// ...and wait for the counter thread to actually die.
			// This way we avoid race condititions where we have lots
			// of dying threads left over that never actually exit and
			// the JVM runs out of resources.
			while (cth.isAlive()) {
				try {
					cth.join();
				} catch (InterruptedException e) {
				}
			}
		}

	}

	@Override
	protected void instantiate() {
		// TODO Auto-generated method stub

	}

	@Override
	protected void uninstantiate() {
		// TODO Auto-generated method stub

	}

	@Override
	public String toString() {
		return TRNG.THREADS_AND_COUNTER.name();
	}

	@Override
	public int minlen() {
		return ONE_BYTE;

	}

	/**
	 * The thread that increments our counter. This increments the (volatile)
	 * counter as fast as it can, yield()ing after each increment, and we sample
	 * that counter value in our main thread.
	 * <p>
	 * We exit when the pleaseStop value is set to true.
	 */
	private static final class CounterThread extends Thread {
		/**
		 * Written to by only this thread; read elsewhere to sample it.
		 * Increments monotonically.
		 * <p>
		 * Start it with a non-zero value to help avoid having a bias in the
		 * value of the initial bit generated.
		 */
		volatile int counter = (int) System.currentTimeMillis();

		/** Only read by this thread; set externally to true to force exit. */
		volatile boolean pleaseStop;

		/**
		 * Increment counter as fast as possible while yield()ing CPU often. The
		 * counter is volatile so that it can be accurately sampled from the
		 * main thread without locking.
		 */
		public final void run() {
			while (!pleaseStop) {
				++counter;
				Thread.yield(); // Give CPU back to main thread at least!
			}
		}
	}
}
