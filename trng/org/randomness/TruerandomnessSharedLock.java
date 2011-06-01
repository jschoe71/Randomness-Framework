package org.randomness;

import java.nio.ByteBuffer;
import java.util.concurrent.locks.ReentrantLock;

public class TruerandomnessSharedLock extends Truerandomness {

	// Lock to prevent concurrent modification of the RNG's internal state.
	private final ReentrantLock lock = new ReentrantLock();

	@Override
	public void reset() {
		// TODO Auto-generated method stub

	}

	@Override
	public int read(ByteBuffer buffer) {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	public void close() {
		// TODO Auto-generated method stub

	}

	@Override
	public boolean isOpen() {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public int tryRead(ByteBuffer buffer) {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	public String toString() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public int minlen() {
		// TODO Auto-generated method stub
		return 0;
	}

}
