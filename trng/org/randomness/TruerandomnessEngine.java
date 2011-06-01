package org.randomness;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.AsynchronousCloseException;
import java.nio.channels.ClosedByInterruptException;

import sun.nio.ch.Interruptible;

/**
 * Internal implementation of {@link Truerandomness} abstract class.
 * 
 * @author Anton Kabysh
 * 
 */
abstract class TruerandomnessEngine extends Truerandomness /* AbstractInterruptibleChannel */{
	// implementation is inspired from
	// java.nio.channels.spi.AbstractInterruptibleChannel;

	private Object closeLock = new Object();
	/**
	 * Indicate if this TRNG is open to produce randomness.
	 */
	private volatile boolean open = true;

	@Override
	public int tryRead(ByteBuffer buffer) {
		return this.read(buffer);
	}

	/**
	 * Closes this channel.
	 * 
	 * <p>
	 * If the channel has already been closed then this method returns
	 * immediately. Otherwise it marks the channel as closed and then invokes
	 * the {@link #implCloseChannel implCloseChannel} method in order to
	 * complete the close operation.
	 * </p>
	 * 
	 * @throws IOException
	 *             If an I/O error occurs
	 */
	public final void close() {
		synchronized (closeLock) {
			if (!open)
				return;
			open = false;
			uninstantiate();
		}
	}

	@Override
	public final void reset() {
		open = true;
		this.instantiate();
	}

	protected abstract void instantiate();

	/**
	 * Closes this channel.
	 * 
	 * <p>
	 * This method is invoked by the {@link #close close} method in order to
	 * perform the actual work of closing the channel. This method is only
	 * invoked if the channel has not yet been closed, and it is never invoked
	 * more than once.
	 * 
	 * <p>
	 * An implementation of this method must arrange for any other thread that
	 * is blocked in an I/O operation upon this channel to return immediately,
	 * either by throwing an exception or by returning normally.
	 * </p>
	 * 
	 * @throws IOException
	 *             If an I/O error occurs while closing the channel
	 */
	protected abstract void uninstantiate();

	public final boolean isOpen() {
		return open;
	}

	// -- Interruption machinery --

	private Interruptible interruptor;
	private volatile boolean interrupted = false;

	/**
	 * Marks the beginning of an I/O operation that might block indefinitely.
	 * 
	 * <p>
	 * This method should be invoked in tandem with the {@link #end end} method,
	 * using a <tt>try</tt>&nbsp;...&nbsp;<tt>finally</tt> block as shown <a
	 * href="#be">above</a>, in order to implement asynchronous closing and
	 * interruption for this channel.
	 * </p>
	 */
	protected final void begin() {
		if (interruptor == null) {
			interruptor = new Interruptible() {
				public void interrupt() {
					synchronized (closeLock) {
						if (!open)
							return;
						interrupted = true;
						open = false;

						TruerandomnessEngine.this.uninstantiate();

					}
				}
			};
		}
		blockedOn(interruptor);
		if (Thread.currentThread().isInterrupted())
			interruptor.interrupt();
	}

	/**
	 * Marks the end of an I/O operation that might block indefinitely.
	 * 
	 * <p>
	 * This method should be invoked in tandem with the {@link #begin begin}
	 * method, using a <tt>try</tt>&nbsp;...&nbsp;<tt>finally</tt> block as
	 * shown <a href="#be">above</a>, in order to implement asynchronous closing
	 * and interruption for this channel.
	 * </p>
	 * 
	 * @param completed
	 *            <tt>true</tt> if, and only if, the I/O operation completed
	 *            successfully, that is, had some effect that would be visible
	 *            to the operation's invoker
	 * 
	 * @throws AsynchronousCloseException
	 *             If the channel was asynchronously closed
	 * 
	 * @throws ClosedByInterruptException
	 *             If the thread blocked in the I/O operation was interrupted
	 */
	protected final void end(boolean completed)
			throws AsynchronousCloseException {
		blockedOn(null);
		if (completed) {
			interrupted = false;
			return;
		}
		if (interrupted)
			throw new ClosedByInterruptException();
		if (!open)
			throw new AsynchronousCloseException();
	}

	// -- sun.misc.SharedSecrets --
	static void blockedOn(Interruptible intr) { // package-private
		sun.misc.SharedSecrets.getJavaLangAccess().blockedOn(
				Thread.currentThread(), intr);
	}
}
