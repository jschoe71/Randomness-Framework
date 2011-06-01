package org.randomness;

import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.awt.event.KeyListener;
import java.nio.ByteBuffer;

class KeyboardTiming extends TruerandomnessEngine implements KeyListener {

	protected byte[] mSeed;
	protected int mBitIndex;
	protected boolean mDone;
	protected char mLastKeyChar;
	protected ActionListener mListenerChain;
	protected Counter mCounter;

	@Override
	protected void instantiate() {
		int seedBytes = 80;
		mSeed = new byte[seedBytes];
		mBitIndex = seedBytes * 8 - 1;
		mDone = false;
		mLastKeyChar = '\0';
		mListenerChain = null;
		mCounter = new Counter();
	}

	@Override
	public int read(ByteBuffer buffer) {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	protected void uninstantiate() {
		// TODO Auto-generated method stub

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

	@Override
	public void keyPressed(KeyEvent e) {
		// TODO Auto-generated method stub

	}

	@Override
	public void keyReleased(KeyEvent e) {
		// TODO Auto-generated method stub

	}

	@Override
	public void keyTyped(KeyEvent e) {
		// TODO Auto-generated method stub

	}

	public class Counter implements Runnable {
		protected boolean mTrucking;
		protected int mCounter;

		public Counter() {
			mTrucking = true;
			mCounter = 0;
			Thread t = new Thread(this);
			t.start();
		}

		public void run() {
			while (mTrucking) {
				mCounter++;
				try {
					Thread.sleep(1);
				} catch (InterruptedException ie) {
				}
			}
		}

		public void stop() {
			mTrucking = false;
		}

		public int getCount() {
			return mCounter;
		}
	}

}
