package org.randomness;

import java.io.File;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.nio.channels.AsynchronousCloseException;
import java.nio.channels.NonReadableChannelException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Enumeration;
import java.util.Properties;

/**
 * This class gathers miscellaneous system information, some machine dependent,
 * some not; this information is then hashed together with the 20 seed bytes.
 * 
 * @author Anton Kabysh
 * @author Joshua Bloch
 * @author Gadi Guy
 */
final class SystemEntropy extends TruerandomnessEngine {

	private static final int SHA_HASH_BYTES = 20; // bytes.

	// Mask for casting a byte to an int, bit-by-bit (with
	// bitwise AND) with no special consideration for the sign bit.
	private static final int BITWISE_BYTE_TO_INT = 0x000000FF;

	@Override
	public final int nextInt() { // non effective, used buffered instead.
		byte[] bytes = getPersonalizedSystemEntropy();
		return (BITWISE_BYTE_TO_INT & bytes[3])
				| ((BITWISE_BYTE_TO_INT & bytes[2]) << 8)
				| ((BITWISE_BYTE_TO_INT & bytes[1]) << 16)
				| ((BITWISE_BYTE_TO_INT & bytes[0]) << 24);
	}

	@Override
	public final long nextLong() { // non effective, used buffered instead.
		byte[] bytes = getPersonalizedSystemEntropy();
		long value = 0;
		for (int i = 0; i < LONG_SIZE_BYTES; i++) {
			byte b = bytes[i];
			value <<= 8;
			value += b;
		}
		return value;
	}

	@Override
	public final int read(final ByteBuffer buffer) {
		boolean completed = false;

		try {
			begin();

			final int rem = buffer.remaining();
			// TODO optimize
			for (int bytes = 0, len = rem; bytes < len;) {
				byte[] rnd = getPersonalizedSystemEntropy(); // TODO handle
																// exceptions

				if (len - bytes >= SHA_HASH_BYTES) {
					buffer.put(rnd);
					bytes += SHA_HASH_BYTES; // add 20-bytes
				} else {
					for (int i = 0, n = len - bytes; n-- > 0; i++, bytes++)
						buffer.put(rnd[i]);
				}
			}

			completed = true;

			return rem;
		} finally {
			try {
				end(completed);
			} catch (AsynchronousCloseException e) {
				// TODO Auto-generated catch block
			}
		}
	}

	private final byte[] getPersonalizedSystemEntropy() {
		final MessageDigest md;

		try {
			md = MessageDigest.getInstance("SHA");
		} catch (NoSuchAlgorithmException nsae) {
			throw new InternalError("internal error: SHA-1 not available.");
		}

		// The current time in millis
		byte b = (byte) System.currentTimeMillis();
		md.update(b);

		// personal hash
		md.update((byte) System.identityHashCode(this));

		java.security.AccessController
				.doPrivileged(new java.security.PrivilegedAction<Void>() {
					public Void run() {
						// TODO more entropy ???
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

	@Override
	protected void instantiate() {
		// TODO Auto-generated method stub
	}

	@Override
	protected void uninstantiate() {
		// TODO Auto-generated method stub

	}

	@Override
	public int minlen() {
		return SHA_HASH_BYTES;

	}

	@Override
	public final String toString() {
		return TRNG.SYSTEM_INFORMATION.name();
	}

}
