package org.randomness;

import java.nio.ByteBuffer;
import java.nio.channels.NonReadableChannelException;

/**
 * In this technique entropy produced by counting the number of times the VM
 * manages to loop in a given period.
 * 
 * @author Anton Kabysh
 * @author Joshua Bloch
 * @author Gadi Guy
 * 
 */
// http://www.docjar.com/html/api/sun/security/provider/SeedGenerator.java.html
class ThreadedEntropy extends TruerandomnessEngine implements Runnable {

	// Queue is used to collect seed bytes
	private byte[] pool;
	private int start, end, count;

	// Thread group for our threads
	private ThreadGroup seedGroup;
	Thread thisThread;

	/**
	 * The constructor is only called once to construct the one instance we
	 * actually use. It instantiates the message digest and starts the thread
	 * going.
	 */
	ThreadedEntropy() {
	}

	/**
	 * This method does the actual work. It collects random bytes and pushes
	 * them into the queue.
	 */
	final public void run() {
		try {
			while (isOpen() && !thisThread.isInterrupted()) { // FIXME test stop
																// and close
				// Queue full? Wait till there's room.
				synchronized (this) {
					while (count >= pool.length)
						wait();
				}

				int counter, quanta;
				byte v = 0;

				// Spin count must not be under 64000
				for (counter = quanta = 0; (counter < 64000) && (quanta < 6); quanta++) {

					// Start some noisy threads
					try {
						BogusThread bt = new BogusThread();
						Thread t = new Thread(seedGroup, bt,
								"ThreadedEntropy Thread");
						t.start();
					} catch (Exception e) {
						throw new InternalError("internal error: "
								+ "ThreadedEntropy thread creation error.");
					}

					// We wait 250milli quanta, so the minimum wait time
					// cannot be under 250milli.
					int latch = 0;
					latch = 0;
					long l = System.currentTimeMillis() + 250;
					while (System.currentTimeMillis() < l) {
						synchronized (this) {
						}
						;
						latch++;
					}

					// Translate the value using the permutation, and xor
					// it with previous values gathered.
					v ^= rndTab[latch % 255];
					counter += latch;
				}

				// Push it into the queue and notify anybody who might
				// be waiting for it.
				synchronized (this) {
					pool[end] = v;
					end++;
					count++;
					if (end >= pool.length)
						end = 0;

					notifyAll();
				}
			}
		} catch (Exception e) {
			throw new InternalError("internal error: "
					+ "ThreadEntropy generated an exception.");
		}
	}

	// The permutation was calculated by generating 64k of random
	// data and using it to mix the trivial permutation.
	// It should be evenly distributed. The specific values
	// are not crucial to the security of this class.
	private static byte[] rndTab = { 56, 30, -107, -6, -86, 25, -83, 75, -12,
			-64, 5, -128, 78, 21, 16, 32, 70, -81, 37, -51, -43, -46, -108, 87,
			29, 17, -55, 22, -11, -111, -115, 84, -100, 108, -45, -15, -98, 72,
			-33, -28, 31, -52, -37, -117, -97, -27, 93, -123, 47, 126, -80,
			-62, -93, -79, 61, -96, -65, -5, -47, -119, 14, 89, 81, -118, -88,
			20, 67, -126, -113, 60, -102, 55, 110, 28, 85, 121, 122, -58, 2,
			45, 43, 24, -9, 103, -13, 102, -68, -54, -101, -104, 19, 13, -39,
			-26, -103, 62, 77, 51, 44, 111, 73, 18, -127, -82, 4, -30, 11, -99,
			-74, 40, -89, 42, -76, -77, -94, -35, -69, 35, 120, 76, 33, -73,
			-7, 82, -25, -10, 88, 125, -112, 58, 83, 95, 6, 10, 98, -34, 80,
			15, -91, 86, -19, 52, -17, 117, 49, -63, 118, -90, 36, -116, -40,
			-71, 97, -53, -109, -85, 109, -16, -3, 104, -95, 68, 54, 34, 26,
			114, -1, 106, -121, 3, 66, 0, 100, -84, 57, 107, 119, -42, 112,
			-61, 1, 48, 38, 12, -56, -57, 39, -106, -72, 41, 7, 71, -29, -59,
			-8, -38, 79, -31, 124, -124, 8, 91, 116, 99, -4, 9, -36, -78, 63,
			-49, -67, -87, 59, 101, -32, 92, 94, 53, -41, 115, -66, -70, -122,
			50, -50, -22, -20, -18, -21, 23, -2, -48, 96, 65, -105, 123, -14,
			-110, 69, -24, -120, -75, 74, 127, -60, 113, 90, -114, 105, 46, 27,
			-125, -23, -44, 64 };

	@Override
	public int nextInt() {
		return (int) ((((nextByte() & 0xff) << 24) //
				| ((nextByte() & 0xff) << 16) | //
				((nextByte() & 0xff) << 8) | //
		((nextByte() & 0xff) << 0)));
	}

	@Override
	public int read(ByteBuffer buffer) {

		final int rem = buffer.remaining();

		while (buffer.hasRemaining()) {
			buffer.put(nextByte());
		}

		return rem;
	}

	@Override
	public final String toString() {
		return "TRNG.THREADS_SYNCHRONIZATION";
	}

	@Override
	public final byte nextByte() {

		byte b = 0;
		try {
			// Wait for it...
			synchronized (this) {
				while (count <= 0)
					wait();
			}
		} catch (Exception e) {
			if (count <= 0)
				throw new InternalError(
						"internal error: "
								+ "Thread synchronization entropy generated an exception.");
		}

		synchronized (this) {
			// Get it from the queue
			b = pool[start];
			pool[start] = 0;
			start++;
			count--;
			if (start == pool.length)
				start = 0;

			// Notify the daemon thread, just in case it is
			// waiting for us to make room in the queue.
			notifyAll();
		}

		return b;
	}

	@Override
	public int minlen() {
		return ONE_BYTE;
	}

	@Override
	protected void instantiate() {
		pool = new byte[20];
		start = end = 0;

		final ThreadGroup[] finalsg = new ThreadGroup[1];

		Thread t = java.security.AccessController
				.doPrivileged(new java.security.PrivilegedAction<Thread>() {
					public Thread run() {
						ThreadGroup parent, group = Thread.currentThread()
								.getThreadGroup();
						while ((parent = group.getParent()) != null)
							group = parent;
						finalsg[0] = new ThreadGroup(group,
								"ThreadedEntropy ThreadGroup");
						Thread newT = thisThread = new Thread(finalsg[0],
								ThreadedEntropy.this, "ThreadedEntropy Thread");
						newT.setPriority(Thread.MIN_PRIORITY);
						newT.setDaemon(true);
						return newT;
					}
				});
		seedGroup = finalsg[0];
		t.start();
	}

	@Override
	protected void uninstantiate() {
		pool = null;
		thisThread.interrupt();
		thisThread = null;
		seedGroup.interrupt();
		seedGroup = null;
	}

	/**
	 * This inner thread causes the thread scheduler to become 'noisy', thus
	 * adding entropy to the system load. At least one instance of this class is
	 * generated for every seed byte.
	 */

	private static class BogusThread implements Runnable {
		final public void run() {
			try {
				for (int i = 0; i < 5; i++)
					Thread.sleep(50);
				// System.gc();
			} catch (Exception e) {
			}
		}
	}

}
