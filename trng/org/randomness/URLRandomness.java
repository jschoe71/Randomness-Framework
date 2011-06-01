package org.randomness;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.NonReadableChannelException;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Read randomness from specified URL.
 * 
 * @author Anton Kabysh
 * 
 */
abstract class URLRandomness extends TruerandomnessEngine {

	@Override
	public final int nextInt() { // should never been used
		ByteBuffer buffer; // loosing performance
		read(buffer = ByteBuffer.allocate(INT_SIZE_BYTES));
		buffer.rewind();
		return buffer.getInt();
	}

	@Override
	public final long nextLong() { // should never been used
		ByteBuffer buffer; // loosing performance
		read(buffer = ByteBuffer.allocate(LONG_SIZE_BYTES));
		buffer.rewind();
		return buffer.getInt();
	}

	@Override
	protected void instantiate() {
		// TODO Auto-generated method stub

	}

	@Override
	public final int read(ByteBuffer buffer) {

		int bytes = 0;
		final int rem = buffer.remaining();

		try {
			final int max = maximumRequest();

			for (int toRead = 0, len = rem; bytes < len;) {
				if (len - bytes >= max)
					toRead = max;
				else
					toRead = len - bytes;

				recieveBytes(buffer, toRead);
				bytes += toRead;
			}

		} catch (IOException e) {
			throw new InternalError(e.toString());
		} catch (SecurityException ex) {
			// Might be thrown if resource access is restricted (such as in an
			// applet sandbox).
			throw new SecurityException("SecurityManager prevented access to "
					+ toString(), ex);
		} finally {
		}

		return bytes;
	}

	abstract int maximumRequest();

	abstract void recieveBytes(ByteBuffer buffer, int requiredBytes)
			throws IOException;

}
