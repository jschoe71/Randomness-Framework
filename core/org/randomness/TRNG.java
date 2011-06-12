package org.randomness;

import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.BitSet;
import java.util.ConcurrentModificationException;
import java.util.Enumeration;
import java.util.Properties;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.Lock;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;

/**
 * List of implemented <i>True Random Number Generators</i> - a sources of
 * unpredictable data. <br>
 * <h3 align="center"><i>PROVISIONAL API, WORK IN PROGRESS</i></h3>
 * <p>
 * An appropriate TRNG produces output that is fully dependent on some
 * unpredictable physical source that produces <i>entropy</i>. Contrast with a
 * {@linkplain PRNG PRNG}.<br>
 * <p>
 * <b>Thanks to many people contributed his works and ideas into
 * Truerandomness:</b>
 * 
 * @author <a href="mailto:anton.kabysh@gmail.com">Anton Kabysh</a> (randomness
 *         adaptation)
 * @author <br>
 *         Joshua Bloch, Gadi Guy ({@linkplain TRNG#THREADS_SYNCHRONIZATION
 *         threads synchronization}, {@linkplain TRNG#SYSTEM_INFORMATION system
 *         entropy} )
 * @author <br>
 *         Daniel Dyer ( {@linkplain TRNG#RANDOM_ORG random.org} - original <a
 *         href="https://uncommons-maths.dev.java.net">uncommons-math</a>
 *         <code>RandomDotOrgSeedGenerator</code>)
 * @author <br>
 *         Damon Hart-Davis ( {@linkplain TRNG#THREADS_AND_COUNTER threaded
 *         entropy} - <code>Entropy Pool</code> version)
 * @author <br>
 *         The {@linkplain TRNG#THREADS_AND_COUNTER threaded entropy} algorithm
 *         is based on an idea of Marcus Lippert.
 * @author <br> {@linkplain #QRBG} service created by Radomir Stevanović (Center
 *         for Informatics and Computing, Ruđer Bošković Institute) and Mario
 *         Stipčević (Division of experimental physics, Ruđer Bošković
 *         Institute).
 * @author <br>
 *         <a href="http://www.random.org/mads/">Mads Haahr</a> (parts of TRNG
 *         javadoc description)
 * @author <br>
 *         Doug Lea (idea and implementation of
 *         <code>java.util.concurrent.ThreadLocalRandom</code>)
 * 
 * @see <a
 *      href="http://en.wikipedia.org/wiki/Hardware_random_number_generator">Wikipedia
 *      - Hardware random number generator</a>
 * 
 * @see <a
 *      href="http://en.wikipedia.org/wiki/Entropy_%28information_theory%29">Wikipedia
 *      - Entropy (information theory)</a>
 * 
 * @see <a href="http://en.wikipedia.org/wiki/Next-bit_test">Wikipedia - Next
 *      bit test</a>
 */
public enum TRNG/* implements Generator, Closeable */{
	/**
	 * In this technique entropy produced by counting the number of times the VM
	 * manages to loop in a given period. This number roughly reflects the
	 * machine load at that point in time. The samples are translated using a
	 * permutation (s-box) and then XORed together. This process is non linear
	 * and should prevent the samples from "averaging out". The s-box was
	 * designed to have even statistical distribution; it's specific values are
	 * not crucial for the security of the seed. We also create a number of
	 * sleeper threads which add entropy to the system by keeping the scheduler
	 * busy. Twenty such samples should give us roughly 160 bits of randomness.
	 * These values are gathered in the background by a daemon thread thus
	 * allowing the system to continue performing it's different activites,
	 * which in turn add entropy to the random seed.
	 * <p>
	 * <b>Recommended buffer size from 0 to 20 bytes. Entropy produced
	 * byte-by-byte, so its very time dependent and slowly.</b>
	 * 
	 * @see <a
	 *      href="http://www.docjar.com/html/api/sun/security/provider/SeedGenerator.java.html">SeedGenerator
	 *      Source code</a>
	 */
	THREADS_SYNCHRONIZATION(20) {
		@Override
		public Truerandomness newInstance() {
			try {
				return (Truerandomness) Class.forName(
						"org.randomness.ThreadedEntropy").newInstance();
			} catch (Exception e) {
				// hide, log;
			}
			return null; // not present in the system.
		}
	},
	/**
	 * This technique gathers into buffer miscellaneous system information, some
	 * machine dependent, some not, and hash it using SHA hash. It is <b>not
	 * recommended</b> to use this TRNG in a critical secure points (e.g. as a
	 * seed for {@linkplain CSPRNG}), because system information has low
	 * entropy. But this TRNG can be very useful in combination with other TRNG
	 * as a <a
	 * href="http://en.wikipedia.org/wiki/Cryptographic_nonce">Nonce</a>.
	 * <p>
	 * <b>Recommended buffer size - 20 bytes, entropy produced by 20 bytes
	 * word.</b>
	 * 
	 * @see <a
	 *      href="http://www.docjar.com/html/api/sun/security/provider/SeedGenerator.java.html">Source
	 *      code</a>
	 */
	SYSTEM_INFORMATION(20) {
		@Override
		public Truerandomness newInstance() {
			return new SystemEntropy();
		}
	},
	/**
	 * Default TRNG implementation that uses Java's bundled {@link SecureRandom}
	 * RNG to generate random data in the way depending on native platform ( it
	 * can be <tt>CryptoAPI</tt> call on Windows, read from <tt>dev/random</tt>
	 * on Linux, or other). This is the only entropy strategy that is guaranteed
	 * to work on all platforms.
	 * <p>
	 * <b>Vary from platform to platform, Default buffer size - 20 bytes. Good
	 * quality entropy, should be fast.</b>
	 * <p>
	 * 
	 * @see <a
	 *      href="http://www.javamex.com/tutorials/random_numbers/seeding_entropy.shtml">Seeding
	 *      random number generators (ctd): looking for entropy</a>
	 */
	NATIVE(20) {
		@Override
		public Truerandomness newInstance() {
			return new NativeEntropy();
		}
	},
	/**
	 * TRNG strategy that gets random data from {@literal /dev/random} on
	 * systems that provide it (Solaris/Linux). If {@literal /dev/random} does
	 * not exist or is not accessible, a {@link UnsupportedOperationException}
	 * with comments is thrown.
	 * <p>
	 * Implementation try's to read's number of bytes from beginning of the file
	 * to the <code>byte buffer</code>. It can throw
	 * {@link UnsupportedOperationException} if we can't create file lock,
	 * {@link InternalError} if we can't read bytes from file, and
	 * {@link IllegalStateException} if file lock can't be released.
	 * 
	 * <p>
	 * <b>{@literal /dev/random} must present in system. Default buffer size -
	 * 512 bytes.</b>
	 * <p>
	 * 
	 * @see <a href="http://en.wikipedia.org/wiki//dev/random">Wikipedia -
	 *      /dev/random</a>
	 */
	DEV_RANDOM(512) {
		@Override
		public Truerandomness newInstance() {
			return new FileRandomness(FileRandomness.DEV_RANDOM);
		}
	},
	/**
	 * TRNG strategy that gets random data from unblocking
	 * {@literal /dev/urandom} on systems that provide it (Solaris/Linux). If
	 * {@literal /dev/urandom} does not exist or is not accessible, a
	 * {@link UnsupportedOperationException} with comments is thrown.
	 * <p>
	 * Implementation try's to read's number of bytes from beginning of the file
	 * to the <code>byte buffer</code>. It can throw
	 * {@link UnsupportedOperationException} if we can't create file lock,
	 * {@link InternalError} if we can't read bytes from file, and
	 * {@link IllegalStateException} if file lock can't be released.
	 * 
	 * <p>
	 * <b>Not buffered, {@literal /dev/urandom} must present in system.</b>
	 * <p>
	 * 
	 * @see <a href="http://en.wikipedia.org/wiki//dev/random">Wikipedia -
	 *      /dev/urandom</a>
	 */
	DEV_URANDOM(1024) {
		@Override
		public Truerandomness newInstance() {
			return new FileRandomness(FileRandomness.DEV_URANDOM);
		}
	},
	/**
	 * <a href="http://www.random.org" target="_top">RANDOM.ORG</a> is a true
	 * random number service that generates randomness via atmospheric noise.
	 * The randomness comes from atmospheric noise, which for many purposes is
	 * better than the pseudo-random number algorithms typically used in
	 * computer programs. RANDOM.ORG uses a simple <a
	 * href="http://www.random.org/quota/">quota system</a> to make sure nobody
	 * hogs all the random numbers produced by the generator. You get a free
	 * top-up of up to 200,000 bits every day (just after midnight UTC) until
	 * you reach the default allowance of 1,000,000 bits. If the server is
	 * lightly loaded, you may get a free top-up earlier, but don't count on it.
	 * <p>
	 * Connects to the website (via HTTPS) and downloads a set of random bits.
	 * It is generally better to use the {@link TRNG#DEV_RANDOM} where possible,
	 * as it should be much quicker. This seed generator is most useful on
	 * Microsoft Windows and other platforms that do not provide
	 * {@link TRNG#DEV_RANDOM /dev/random}.
	 * <p>
	 * <b>Recommended buffer size - 1024 bytes (max allowance 1,000,000 bits per
	 * request, or 10000 ints), very good quality entropy. Connection via HTTPS
	 * must be open, or exception will be thrown.</b>
	 * 
	 * @see <a href="http://www.random.org/">RANDOM.ORG - True Random Number
	 *      Service</a>
	 */
	RANDOM_ORG(1024) {
		@Override
		public Truerandomness newInstance() {
			return new AtmosfericNoiseEntropy();
		}
	}, // maximum 2048
	/**
	 * Obtains genuine random data from <a href="http://www.fourmilab.ch/">John
	 * Walker</a>'s <a href="http://www.fourmilab.ch/hotbits/">HotBits</a>
	 * radioactive decay random sequence generator. <cite>HotBits</cite> is an
	 * Internet resource that brings <em>genuine</em> random numbers, generated
	 * by a process fundamentally governed by the inherent uncertainty in the
	 * quantum mechanical laws of nature, directly to your computer in a variety
	 * of forms. <cite>HotBits</cite> are generated by timing successive pairs
	 * of radioactive decays detected by a Geiger-Muller tube interfaced to a
	 * computer. You order up your serving of HotBits by <a
	 * href="https://www.fourmilab.ch/hotbits/secure_generate.html">filling out
	 * a request form</a> specifying how many random bytes you want and in which
	 * format you'd like them delivered. Your request is relayed to the HotBits
	 * server, which flashes the random bytes back to you over the Web. Since
	 * the <a href="hardware.html">HotBits generation hardware</a> produces data
	 * at a modest rate (about 100 bytes per second), requests are filled from
	 * an &ldquo;inventory&rdquo; of pre-built HotBits. Once the random bytes
	 * are delivered to you, they are immediately discarded&mdash;the same data
	 * will never be sent to any other user and no records are kept of the data
	 * at this or any other site. (Of course, if you're using the random data
	 * for cryptography or other security-related applications, you can't be
	 * <em>certain</em> I'm not squirreling away a copy. But I'm not, really.)
	 * 
	 * <p>
	 * <b>Buffer size - 1024 bytes (maximum 2048 per request). Very good quality
	 * entropy. Connection via HTTPS must be open, or exception will be
	 * thrown.</b>
	 * 
	 * @see <a href="http://www.fourmilab.ch/hotbits/">HotBits: Genuine random
	 *      numbers, generated by radioactive decay </a>
	 */
	HOTBITS(1024) {
		@Override
		public Truerandomness newInstance() {
			return new RadioactiveDecayEntropy();
		}
	},

	/**
	 * <i>TODO PROVISIONAL API, WORK IN PROGRESS:</i> Quantum random bit
	 * generator based on photonic emission in semiconductors from Ruđer
	 * Bošković Institute.
	 * <p>
	 * QRBG is a fast, nondeterministic and novel random number generator whose
	 * randomness relies on intrinsic randomness of the quantum physical process
	 * of photonic emission in semiconductors and subsequent detection by the
	 * photo-electric effect. The timing information of detected photons is used
	 * to generate binary random digits - bits, with effciency of nearly 0.5
	 * bits per detected random event. Device consists of a light source (LED),
	 * one single-photon detector and fast electronics for the timing analysis
	 * of detected photons providing random output numbers (bits) at (currently)
	 * 16 Mbit/sec. By using only one photodetector (in contrast to other
	 * similar solutions) there is no need to perform any netuning of the
	 * generator, moreover, the method used is immune to detector instability
	 * problems, which fosters the autonomous work of the service (with- out the
	 * usually required periodic calibrations of the generator). For the purpose
	 * of eliminating correlations, a restartable clock method is used for time
	 * interval measurement.
	 * <p>
	 * The collection of statistical tests (including NIST's "Statistical Test
	 * Suite for Random and Pseudorandom Number Generators for Cryptographic
	 * Applications" and DIEHARD battery of strong statistical randomness tests)
	 * applied to random numbers sequences longer than 1 Gb produced with this
	 * quantum random number generator presents results which demonstrate the
	 * high quality of randomness resulting in bias1 less than 10<sup>-4</sup>,
	 * autocorrelation consistent with zero, near maximal binary entropy and
	 * measured min-entropy near theoretical maximum. For much more details on
	 * these and other performed tests results, see publications on the main
	 * site.
	 * 
	 * @see <a href="http://random.irb.hr">Quantom Random Bit Generator
	 *      Service</a>
	 */
	QRBG(50) {
		@Override
		Truerandomness newInstance() {
			// TODO Auto-generated method stub
			return null;
		}
	},
	/**
	 * Generate entropy using Thread synchronization and counter to generate
	 * random bytes, its following the same sort of strategy as the
	 * {@linkplain TRNG#THREADS_SYNCHRONIZATION thread synchronization} entropy
	 * generator, but not so expensive in terms of CPU time and always generates
	 * new entropy each time.
	 * <p>
	 * 
	 * This implementation uses two threads A and B. A starts B and sleeps for a
	 * certain amount of time (~50 ms). Meanwhile B starts counting up a global
	 * variable. When A wakes up again it stops B and checks if the content of
	 * the global variable is odd (-> generate a '1') or even (-> generate a
	 * '0'). This process is repeated for each bit.
	 * <p>
	 * This is not a good substitute for real external entropy, e.g.
	 * {@linkplain TRNG#RANDOM_ORG random.org} or {@linkplain TRNG#HOTBITS
	 * hotbits}. This may not work with all VMs but attempts to adapt itself to
	 * the current VM and workload to be as robust (and fast) as possible.
	 * <p>
	 * <b>Recommended buffer size - from 0 to 20 bytes. This type of entropy is
	 * very time dependent. Should be faster than
	 * {@link TRNG#THREADS_SYNCHRONIZATION}.</b>
	 * 
	 * @see <a
	 *      href="http://grepcode.com/file/repo1.maven.org/maven2/org.bouncycastle/bcprov-jdk15/1.38/org/bouncycastle/crypto/prng/ThreadedSeedGenerator.java">org.bouncycastle.crypto.prng.ThreadedSeedGenerator</a>
	 */
	THREADS_AND_COUNTER(20) {
		@Override
		public Truerandomness newInstance() {
			try {
				return (Truerandomness) Class.forName(
						"org.randomness.ThreadsAndCounterEntropy")
						.newInstance();
			} catch (Exception e) {
				// hide, log;
			}
			return null; // not present in the system.
		}
	};

	private TRNG(int poolSize) {
		BUFFERLEN = new AtomicInteger(poolSize);
	}

	private static final String PATH = TRNG.class.getPackage().getName();

	/**
	 * A suitable physical phenomenon as entrpy source is atmospheric noise,
	 * which is quite easy to pick up with a normal radio. This is the approach
	 * used by {@linkplain #RANDOM_ORG RANDOM.ORG}.
	 * 
	 * @see <a href="http://en.wikipedia.org/wiki/Noise_(radio)">Wikipedia -
	 *      Atmospheric noise</a>
	 * @see <a href="http://en.wikipedia.org/wiki/Atmospheric_noise">Wikipedia -
	 *      Atmos</a>
	 */
	public static final TRNG ATMSFERIC_NOISE = RANDOM_ORG;
	/**
	 * Radioactive decay is the spontaneous, stochastic (i.e. random) physical
	 * phenomenon suitable to be entropy source based on quantum effects. This
	 * is the approach used by {@link TRNG#HOTBITS HOTBITS}, where entropy
	 * obtained by the beta decay of Cæsium-137 to Barium-137.
	 * 
	 * @see <a href="http://en.wikipedia.org/wiki/Nuclear_decay">Wikipedia -
	 *      Nuclear Decay</a>
	 * @see <a href="http://www.fourmilab.ch/hotbits/how3.html">
	 */
	public static final TRNG RADIOACTIVE_DECAY = HOTBITS;

	/**
	 * Internal instance of this TRNG.
	 */
	// private Truerandomness instance;

	/**
	 * Create's new instance of specified <i>True Random Number Generator</i>
	 * (if supported at initialization time) with default configurable
	 * parameters. This method return's <code>null</code> if specified generator
	 * is not supported by platform at this moment. So, for example if Internet
	 * connection is not open before than
	 * <code>TRNG.RANDOM_ORG.defaultInstance()</code> is called, so calling of
	 * this method is return <code>null</code>.
	 * 
	 * @return a new Truerandomness generator, or <code>null</code> if this
	 *         generator is not supported by platform.
	 * 
	 * @see Truerandomness#shared(TRNG)
	 */
	final Truerandomness defaultInstance() {

		try {
			return newInstance();
		} catch (Throwable t) {
			// hide
		}

		// not supported
		return null;
	}

	// /**
	// * Resets internal instance of <code>this</code> TRNG. If internal
	// instance
	// * is not previously created (e.g. no open connection for RANDOM_ORG),
	// than
	// * it try to re-create this again (without throwing any exceptions).
	// *
	// */
	// public final void reset() {
	// if (instance == null) {
	// try {
	//
	// instance = defaultInstance();
	//
	// } catch (Throwable t) {
	// // hide
	// }
	// } else
	// instance.reset();
	//
	// }

	// /**
	// * Closes this TRNG and releases any system resources associated with it;
	// * Any currently running read function will be gracefully interrupted. If
	// * the stream is already closed then invoking this method has no effect.
	// */
	// @Override
	// public void close() {
	// if (instance != null)
	// instance.close();
	// }

	/**
	 * Determine the recommended TRNG <i>buffer size</i>. You can set this
	 * configurable to new value.
	 * <p>
	 * The default <i>buffer size</i> for all implementer TRNG's:
	 * <table border="0" cellspacing="0">
	 * <th>TRNG
	 * <th>Buffer size
	 * <tr>
	 * <td>{@linkplain TRNG#DEV_RANDOM /DEV/RANDOM}
	 * <td>Any, allowed by system. Default - 512 bytes.
	 * <tr>
	 * <td>{@linkplain TRNG#DEV_URANDOM /DEV/URANDOM}
	 * <td>Any, allowed by system. Default - 1024 bytes.
	 * <tr>
	 * <td>{@linkplain TRNG#HOTBITS HOTBITS}
	 * <td>1024 bytes (maximum 2048 per request)
	 * <tr>
	 * <td>{@linkplain TRNG#NATIVE NATIVE}
	 * <td>Vary for different platforms. Default - 20 bytes.
	 * <tr>
	 * <td>{@linkplain TRNG#RANDOM_ORG RANDOM.ORG}
	 * <td>1024 bytes (max 10000 bytes per request)
	 * <tr>
	 * <td>{@linkplain TRNG#SYSTEM_INFORMATION SYSTEM INFORMATION}
	 * <td>20 bytes
	 * <tr>
	 * <td>{@linkplain TRNG#THREADS_AND_COUNTER THREADS AND COUNTER}
	 * <td>from 0 to 20 bytes
	 * <tr>
	 * <td>{@linkplain TRNG#THREADS_SYNCHRONIZATION THREADS SYNCHRONIZATION}
	 * <td>from 0 to 20 bytes
	 * </table>
	 */
	public final AtomicInteger BUFFERLEN;

	/**
	 * Size of buffer where entropy gathered for
	 * {@linkplain Truerandomness#test() testing} purposes.
	 */
	public final AtomicInteger TEST_BUFFER_SIZE = new AtomicInteger(2048);
	/**
	 * If a block of supposedly-random output can be compressed smaller than
	 * this, we have a problem. This needs to be used thoughtfully, and at best
	 * allows a heuristic check.
	 */
	private final static float MAX_COMPRESSIBILITY = 0.9f;

	/**
	 * Simple and fast check on generated bits; throws an Error if the generator
	 * may be broken. This does a very simple check that some set of `random'
	 * bits that we have generated does appear to be reasonably random.
	 * <p>
	 * This does not alter its input array or copy it anywhere and is designed
	 * to be fast.
	 * <p>
	 * This will ignore very short arrays where its has no reasonable chance of
	 * detecting faulty output. Our threshold is about 8 bytes.
	 * <p>
	 * The possible indicators of faulty generation looked for are:
	 * <ul>
	 * <li>All bytes the same (eg zeros), probability 1 in 256^(n-1) where n is
	 * number of bytes in sample
	 * <li>Significant compressibility possible by a good compressor (gzip)
	 * </ul>
	 * <p>
	 * This needs to be used thoughtfully...
	 * 
	 * @param bits
	 *            the byte array to be tested.
	 * 
	 * @throws Error
	 *             if it looks like the generator may be grossly faulty.
	 */
	public static boolean checkGeneratedBits(byte bits[]) throws Error {
		// Don't bother looking if input is too short to check sensibly.
		if (bits.length < 8) {
			throw new IllegalArgumentException();
		}

		// If requested, do more extensive and slower tests.
		// This runs a slight risk of leaking some sensitive information to
		// the outside world so may not always be appropriate.

		// Attempt to compress the data.
		byte cdata[] = compressData(bits);

		System.out.println(cdata.length + "	:	" + bits.length
				* MAX_COMPRESSIBILITY);
		if (cdata.length < bits.length * MAX_COMPRESSIBILITY)
			return false;
		// throw new Error(
		// "bit source may be broken: data too compressible");
		else
			// Data looks OK!
			return true;

	}

	/**
	 * Generate entropy collected from various system sources e.g. time, date,
	 * memory loading and processed via SHA-1 cryptosecure hash function.
	 * 
	 * @return 20 byte hashed system entropy
	 */
	public static final byte[] getSystemEntropy() {

		final MessageDigest md;

		try {
			md = MessageDigest.getInstance("SHA");
		} catch (NoSuchAlgorithmException nsae) {
			throw new InternalError("internal error: SHA-1 not available.");
		}

		// The current time in millis
		byte b = (byte) System.currentTimeMillis();
		md.update(b);

		java.security.AccessController
				.doPrivileged(new java.security.PrivilegedAction<Void>() {
					public Void run() {

						try {
							// System properties can change from machine to
							// machine
							String s;
							Properties p = System.getProperties();
							Enumeration<?> e = p.propertyNames();
							while (e.hasMoreElements()) {
								s = (String) e.nextElement();
								md.update(s.getBytes());
								md.update(p.getProperty(s).getBytes());
							}

							md.update(InetAddress.getLocalHost().toString()
									.getBytes());

							// The temporary dir
							File f = new File(p.getProperty("java.io.tmpdir"));
							String[] sa = f.list();
							for (int i = 0; i < sa.length; i++)
								md.update(sa[i].getBytes());

						} catch (Exception ex) {
							md.update((byte) ex.hashCode());
						}

						// get Runtime memory stats
						Runtime rt = Runtime.getRuntime();
						byte[] memBytes = longToByteArray(rt.totalMemory());
						md.update(memBytes, 0, memBytes.length);
						memBytes = longToByteArray(rt.freeMemory());
						md.update(memBytes, 0, memBytes.length);

						return null;
					}
				});
		return md.digest();

	}

	/**
	 * Helper function to convert a long into a byte array (least significant
	 * byte first).
	 */
	private static final byte[] longToByteArray(long l) {
		byte[] retVal = new byte[8];

		for (int i = 0; i < 8; i++) {
			retVal[i] = (byte) l;
			l >>= 8;
		}

		return retVal;
	}

	/**
	 * Attempt to compress data with the best algorithm to hand. This may return
	 * the input data untouched.
	 * <p>
	 * We try ZIP maximum compression.
	 * <p>
	 * We allow this to be package visible.
	 */
	static byte[] compressData(byte data[]) {
		if (data.length < 8) {
			return (data);
		} // Too short to compress effectively...
		try {
			// Make a buffer; data expansion is unusual except for short inputs.
			final ByteArrayOutputStream baos = new ByteArrayOutputStream(
					Math.max(data.length, 32));
			final DefOutputStream cos = new DefOutputStream(baos);
			// Write uncompressed data to stream.
			cos.write(data);
			// Force everything out...
			cos.finish();
			cos.flush();
			// Maybe we should strip some other headers too?
			return (baos.toByteArray());
		} catch (IOException e) {
			// Should never happen...
			throw new Error("unexpected internal error");
		}
	}

	/**
	 * Like GZIPOutputStream but no GZIP header or checksum. This is meant to
	 * give maximum compression and assumes error checking/recovery (if any) is
	 * done elsewhere.
	 */
	private final static class DefOutputStream extends DeflaterOutputStream {
		/**
		 * Creates a new output stream with the specified buffer size. Forces
		 * use of the best possible compression at the possible expense of CPU
		 * time.
		 * <p>
		 * This compressed stream is wrapped with neither GZIP nor ZLIB headers
		 * and checksums to minimise overheads; we'd better be doing error
		 * detection and correction elsewhere!
		 * 
		 * @param out
		 *            the output stream
		 * @param size
		 *            the output buffer size
		 * @exception IOException
		 *                if an I/O error has occurred
		 */
		public DefOutputStream(OutputStream out, int size) throws IOException {
			super(out, new Deflater(Deflater.BEST_COMPRESSION, true), size);
		}

		/**
		 * Creates a new output stream with a default buffer size.
		 * 
		 * @param out
		 *            the output stream
		 * @exception IOException
		 *                if an I/O error has occurred
		 */
		public DefOutputStream(OutputStream out) throws IOException {
			this(out, 512);
		}

		/**
		 * Writes array of bytes to the compressed output stream; blocking.
		 * 
		 * @exception IOException
		 *                if an I/O error has occurred
		 */
		public synchronized void write(byte[] buf, int off, int len)
				throws IOException {
			super.write(buf, off, len);
		}

		/**
		 * Finishes writing compressed data to the output stream without closing
		 * it.
		 * 
		 * @exception IOException
		 *                if an I/O error has occurred
		 */
		public synchronized void finish() throws IOException {
			if (!def.finished()) {
				def.finish();
				while (!def.finished()) {
					deflate();
				}
			}
		}

		/**
		 * Writes remaining compressed data to the output stream and closes it.
		 * 
		 * @exception IOException
		 *                if an I/O error has occurred
		 */
		public synchronized void close() throws IOException {
			finish();
			out.close();
		}
	}

	/**
	 * Returns a new <code>Randomness</code> object that implements the
	 * specified entropy gathering mechanism, or True Random Number Generator.
	 * 
	 * @return a new Truerandomness generator
	 */
	abstract Truerandomness newInstance();

	// // ///////////////////////////////////////////////////////////////
	// // ////////////////// GENERATE METHODS ///////////////////////////
	// // ///////////////////////////////////////////////////////////////
	//
	// /**
	// * Return's next generated true random <code>int</code> (32-bit) value.
	// *
	// * @see <a
	// *
	// href="http://java.sun.com/docs/books/jls/third_edition/html/typesValues.html#4.2.1">JLS
	// * - 4.2.1 Integral Types and Values</a>
	// *
	// * @return newly generated true random <code>int</code> value.
	// *
	// * @throws NullPointerException
	// * if generator of current type is not supported by system (e.g.
	// * {@link #DEV_RANDOM} on Windows).
	// */
	// public final int nextInt() {
	// if (instance == null)
	// instance = defaultInstance();
	//
	// return instance.nextInt();
	// }
	//
	// /**
	// * Return's next generated true random <code>boolean</code> (1-bit) value
	// * (typically from <code>nextByte</code> value checking most significant
	// * bit).
	// * <p>
	// * It is important to remember, that <code>boolean</code> values are hold
	// in
	// * platform dependent way (depends from JVM). For large
	// <code>boolean</code>
	// * arrays better to use something like {@link BitSet}.
	// *
	// * @see <a href="http://en.wikipedia.org/wiki/Bit">Wikipedia - Bit</a>
	// * @see <a
	// *
	// href="http://java.sun.com/docs/books/jls/third_edition/html/typesValues.html#4.2.5">JLS
	// * - 4.2.5 The boolean Type and boolean Values</a>
	// * @return newly generated true random boolean value.
	// *
	// * @throws NullPointerException
	// * if generator of current type is not supported by system (e.g.
	// * {@link #DEV_RANDOM} on Windows).
	// */
	// @Override
	// public final boolean nextBoolean() {
	// if (instance == null)
	// instance = defaultInstance();
	//
	// return instance.nextBoolean();
	// }
	//
	// /**
	// * Return's next generated random <code>byte</code> (8-bit) value
	// (typically
	// * from <code>nextInt</code> value using one most significant byte).
	// * <p>
	// * There are several true random generators, essentially producing
	// * <code>byte</code> values:
	// * <ol>
	// * <li>
	// * {@link TRNG#DEV_RANDOM} and {@link TRNG#DEV_URANDOM} (by block's)
	// * <li>
	// * {@link TRNG#THREADS_SYNCHRONIZATION}
	// * </ol>
	// *
	// * @see <a href="http://en.wikipedia.org/wiki/Byte">Wikipedia - Byte</a>
	// * @see <a
	// *
	// href="http://java.sun.com/docs/books/jls/third_edition/html/typesValues.html#4.2.1">JLS
	// * - 4.2.1 Integral Types and Values</a>
	// * @return newly generated true random byte value.
	// *
	// * @throws NullPointerException
	// * if generator of current type is not supported by system (e.g.
	// * {@link #DEV_RANDOM} on Windows).
	// */
	// @Override
	// public final byte nextByte() {
	// if (instance == null)
	// instance = defaultInstance();
	//
	// return instance.nextByte();
	// }
	//
	// /**
	// * Return's next generated, true random <code>char</code> (unsigned
	// 16-bit)
	// * value (typically from <code>nextShort</code> value casting to
	// * <code>char</code> ).
	// *
	// * @see <a
	// *
	// href="http://java.sun.com/docs/books/jls/third_edition/html/typesValues.html#4.2.1">JLS
	// * - 4.2.1 Integral Types and Values</a>
	// *
	// * @return newly generated random <code>char</code> value.
	// *
	// * @throws NullPointerException
	// * if generator of current type is not supported by system (e.g.
	// * {@link #DEV_RANDOM} on Windows).
	// */
	// @Override
	// public final char nextChar() {
	// if (instance == null)
	// instance = defaultInstance();
	//
	// return instance.nextChar();
	// }
	//
	// /**
	// * Return's next generated true random <code>short</code> (16-bit) value
	// * (typically from <code>nextInt</code> value returned two most
	// significant
	// * bytes).
	// *
	// * @see <a
	// *
	// href="http://java.sun.com/docs/books/jls/third_edition/html/typesValues.html#4.2.1">JLS
	// * - 4.2.1 Integral Types and Values</a>
	// *
	// * @return newly generated true random <code>short</code> value.
	// *
	// * @throws NullPointerException
	// * if generator of current type is not supported by system (e.g.
	// * {@link #DEV_RANDOM} on Windows).
	// */
	// @Override
	// public final short nextShort() {
	// if (instance == null)
	// instance = defaultInstance();
	//
	// return instance.nextShort();
	// }
	//
	// /**
	// * Return's next generated, uniformly distributed random
	// <code>double</code>
	// * (64-bit) value between <code>0.0</code> and <code>1.0</code> (taking
	// most
	// * significant 53 bits to mantissa).
	// *
	// * @see <a
	// *
	// href="http://java.sun.com/docs/books/jls/third_edition/html/typesValues.html#4.2.3">JLS
	// * - 4.2.3 Floating-Point Types, Formats, and Values</a>
	// * @see <a href="http://en.wikipedia.org/wiki/IEEE_754-2008">Wikipedia -
	// * IEEE 754</a>
	// * @return newly generated true random <code>double</code> value.
	// *
	// * @throws NullPointerException
	// * if generator of current type is not supported by system (e.g.
	// * {@link #DEV_RANDOM} on Windows).
	// */
	// @Override
	// public final double nextDouble() {
	// if (instance == null)
	// instance = defaultInstance();
	//
	// return instance.nextDouble();
	// }
	//
	// /**
	// * Return's next generated true random <code>float</code> (32-bit) value
	// * between <code>0.0</code> and <code>1.0</code> (taking most significant
	// 24
	// * bits to mantissa from <code>nextInt</code> value).
	// *
	// * @see <a
	// *
	// href="http://java.sun.com/docs/books/jls/third_edition/html/typesValues.html#4.2.3">JLS
	// * - 4.2.3 Floating-Point Types, Formats, and Values</a>
	// * @see <a href="http://en.wikipedia.org/wiki/IEEE_754-2008">Wikipedia -
	// * IEEE 754</a>
	// *
	// * @return newly generated true random <code>float</code> value.
	// *
	// * @throws NullPointerException
	// * if generator of current type is not supported by system (e.g.
	// * {@link #DEV_RANDOM} on Windows).
	// */
	// @Override
	// public final float nextFloat() {
	// if (instance == null)
	// instance = defaultInstance();
	//
	// return instance.nextFloat();
	// }
	//
	// /**
	// * Return's next generated, uniformly distributed random <code>long</code>
	// * (64-bit) value.
	// *
	// * @see <a
	// *
	// href="http://java.sun.com/docs/books/jls/third_edition/html/typesValues.html#4.2.1">JLS
	// * - 4.2.1 Integral Types and Values</a>
	// *
	// * @return newly generated true random <code>long</code> value.
	// *
	// * @throws NullPointerException
	// * if generator of current type is not supported by system (e.g.
	// * {@link #DEV_RANDOM} on Windows).
	// */
	// @Override
	// public final long nextLong() {
	// if (instance == null)
	// instance = defaultInstance();
	//
	// return instance.nextLong();
	// }
	//
	// /**
	// * Generates random block of random bytes and places them into a
	// * user-supplied byte array.
	// * <p>
	// * There are several true random generators, essentially producing block
	// * output:
	// * <ol>
	// * <li> {@link TRNG#THREADS_AND_COUNTER} - requested block
	// * <li> {@link TRNG#SYSTEM_INFORMATION} - blocks per 20 bytes,
	// * <li> {@link TRNG#HOTBITS} and {@link TRNG#RANDOM_ORG} - requested block
	// * allowed by service,
	// * <li> {@link TRNG#NATIVE} - requested block
	// * <li>
	// * {@link TRNG#DEV_RANDOM} - available block
	// * <li>
	// * {@link TRNG#DEV_URANDOM} - requested block
	// * </ol>
	// *
	// * @param bytes
	// * - the byte array to fill with true random bytes
	// *
	// * @throws NullPointerException
	// * if generator of current type is not supported by system (e.g.
	// * {@link #DEV_RANDOM} on Windows).
	// */
	// @Override
	// public final void read(byte[] bytes) {
	// if (instance == null)
	// instance = defaultInstance();
	//
	// instance.read(bytes);
	// }

	/**
	 * Checks whatever or not this entropy source is acessible on current
	 * platform.
	 * <p>
	 * For every platform designed own best {@linkplain #NATIVE native}
	 * generator which works well.
	 * 
	 * <pre>
	 * Truerandomness entropy = null;
	 * if (TRNG.DEV_RANDOM.isSupported())
	 * 	entropy = TRNG.DEV_RANDOM.current();
	 * else
	 * 	entropy = TRNG.NATIVE.current();
	 * </pre>
	 * 
	 * @see CSPRNG#isSupported()
	 * @return <code>true</code> if generators of this type can be instantiated
	 *         on this platform, <code>false</code> otherwise.
	 */
	public boolean isSupported() {

		return defaultInstance() != null;
	}

	/**
	 * <i>TODO PROVISIONAL API, WORK IN PROGRESS:</i> Returns a <b>unique</b>
	 * TRNG entropy generator isolated to the current thread (<i>thread local
	 * random</i>). An attempt to use this instance from annoter thread will
	 * throw {@link ConcurrentModificationException}.
	 * <p>
	 * Usages of this class should typically be of the form:
	 * {@code TRNG.XXX.current().nextX(...)} (where {@code XXX} - one of
	 * implemented TRNG generators, and {@code X} is {@code Int}, {@code Long},
	 * etc). When all usages are of this form, it is never possible to
	 * accidently share a <i>thread local random</i> across multiple threads.
	 * <p>
	 * The thread local random instance is unique for parent thread, so locality
	 * can be cheked as:
	 * 
	 * <pre>
	 * public boolean isThreadLocal(Randomness rnd) {
	 * 	return TRNG.XXX.current() == rnd;
	 * }
	 * </pre>
	 * 
	 * where {@code XXX} - one of implemented TRNG generators
	 * 
	 * @return the thread local instance of TRNG for current thread.
	 * @see ThreadLocal
	 * @see <br>
	 *      PRNG#current() Thread local for Pseudorandomness,
	 * @see <br>
	 *      CSPRNG#current() Thread-local for Cryptorandomness.
	 */
	public synchronized Truerandomness current() {
		throw new UnsupportedOperationException();

		// return localRandom.get();
	}

	/**
	 * The actual ThreadLocal
	 */
	private final ThreadLocal<Truerandomness> localRandom = new ThreadLocal<Truerandomness>() {
		protected Truerandomness initialValue() {
			return defaultInstance();
		}
	};

	/**
	 * <i>TODO PROVISIONAL API, WORK IN PROGRESS:</i>
	 * 
	 * @return
	 */
	public Truerandomness shared() {
		throw new UnsupportedOperationException();
	}

	/**
	 * Returns the 32-bit unpredictable value obtained from hash code value
	 * containing several bits of entropy. It is not a substitution of real
	 * entropy sources, and cannot be used to create generator's seed, as for
	 * cryptographic purposes.
	 * <p>
	 * This method should be used to get fast unpredictable value, with several
	 * bits of entropy for non cryptographic purposes. Random values created
	 * from hash codes obtained from the Ghost-objects (<code>Object</code>
	 * created, return hash code, and garbage collected).
	 * 
	 * @return <i>unique</i> unpredictable 32 bit value from hash code of
	 *         Ghost-objects.
	 */
	public static final int nextHashCodeEntropy() {
		int hash = 17;
		for (int i = 0; i < 11; i++) {
			hash = 37 * hash + new Object().hashCode();
		}
		return hash = 37 * hash + new Object().hashCode();
	}

	/**
	 * <i>PROVISIONAL API, WORK IN PROGRESS:</i> Retunrn's 64-bit unpredictable
	 * value created from system time sources such us
	 * {@link System#currentTimeMillis()} and {@link System#nanoTime()}.
	 * 
	 * @return 32 bit entropy word
	 */
	public static final int nextTimeEntropy() {
		return ((int) System.nanoTime()) ^ ((byte) System.currentTimeMillis());
	}


}
