package org.randomness;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.NonReadableChannelException;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Randomness read from file.
 * 
 * @author Anton Kabysh
 * 
 */
class FileRandomness extends TruerandomnessEngine {

	public static final String DEV_RANDOM = "dev/random";
	public static final String DEV_URANDOM = "dev/urandom";

	private final int FILE_START = 0;

	/**
	 * File channel to specified file
	 */
	private FileChannel fileChannel;
	/**
	 * Name of file with random data.
	 */
	private String fileName;
	/**
	 * Lock to prevent concurrent modifications.
	 */
	Lock lock = new ReentrantLock();

	/**
	 * Create <code>Randomness</code> which read random bytes from specified
	 * file.
	 * 
	 * @param fileName
	 *            Name of file with random data.
	 */
	public FileRandomness(String fileName) {
		this.fileName = fileName;
		reset();
	}

	/**
	 * Try to read's number of bytes from beginning of the file to the
	 * <code>buffer</code>.
	 * 
	 * @param buffer
	 *            a ByteBuffer into which reads bytes from the file.
	 * @return returns the actual number of bytes read.
	 * 
	 * @throws UnsupportedOperationException
	 *             if we can't create file lock.
	 * @throws InternalError
	 *             if we can't read bytes from file.
	 * @throws IllegalStateException
	 *             if file lock can't be released.
	 */
	@Override
	public final int read(final ByteBuffer buffer) {
		if (!isOpen())
			throw new NonReadableChannelException();

		final int requiredBytes = buffer.remaining();

		FileLock fileLock = null;
		try {// create lock
			lock.lock();

			// First, we locking the remaining number bytes of the file.
			fileLock = fileChannel.lock(FILE_START, requiredBytes, true);

		} catch (IOException lockException) {
			throw new UnsupportedOperationException(
					"Failed to create lock over " + fileName, lockException);
		}
		// ok, file lock is accepted
		// Second, we move position of fileChannel to beginning of file
		try {
			fileChannel.position(FILE_START); // reset file channel position
			// Third, reading bytes.
			// returns the actual number of bytes read.
			// it can be less then required if we reach EOF.
			// so, after calling check the if(buffer.remaining() > 0)
			// then not all remaining bytes was read.
			return fileChannel.read(buffer); // try to read

		} catch (IOException readException) {
			throw new InternalError("Failed to read from" + fileName);
		} finally {
			// finally, try to release file lock
			try {
				fileLock.release();
			} catch (IOException releaseException) {
				throw new IllegalStateException(
						"Failed to release lock from file " + fileName,
						releaseException);
			}
			lock.unlock();
		}
	}

	@Override
	protected void uninstantiate() {
		try {
			fileChannel.close();

		} catch (IOException closeEx) {
			throw new UnsupportedOperationException(
					"Failed to close File Channel to " + fileName, closeEx);
		}
	}

	@Override
	protected void instantiate() {
		try { // reopen file channel

			fileChannel = new FileInputStream(fileName).getChannel();

		} catch (FileNotFoundException fileNotFound) {
			throw new UnsupportedOperationException("failed to open "
					+ fileName, fileNotFound);
		}
	}

	@Override
	public final String toString() {
		return fileName.equals(DEV_RANDOM) ? TRNG.DEV_RANDOM.name()
				: TRNG.DEV_URANDOM.name();
	}

	@Override
	public final int minlen() {
		try {
			return (int) fileChannel.size();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} // not specified
		return 0;
	}

	/*
	 * Buffered FileRandomness based on file Mapping into MappedByteBuffer. Need
	 * to be developed and tested.
	 */
	// private final class Buffered extends Randomness.Buffered {
	//
	// public Buffered(int bufferSize) { // inheritance from inner class
	// // parent object must call constructor of inner class.
	// (FileRandomness.this).super(bufferSize);
	// }
	//
	// @Override
	// protected ByteBuffer newBuffer(int bufferSize) {
	// try {
	// if (FileRandomness.this.isOpen())
	// return FileRandomness.this.fileChannel.map(
	// MapMode.READ_ONLY, FILE_START, bufferSize);
	// else
	// throw new NonReadableChannelException();
	//
	// } catch (IOException e) {
	// // some problems, hide.
	// e.printStackTrace();
	// }
	// // use default buffer allocation
	// return super.newBuffer(bufferSize);
	// }
	// }
}
