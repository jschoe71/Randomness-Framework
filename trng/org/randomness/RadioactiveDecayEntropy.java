package org.randomness;

import java.io.IOException;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.ReadableByteChannel;
import java.text.MessageFormat;

/**
 * Obtains genuine random data from <a href="http://www.fourmilab.ch/">John
 * Walker</a>'s <a href="http://www.fourmilab.ch/hotbits/">HotBits</a>
 * radioactive decay random sequence generator.
 * 
 * @author Anton Kabysh
 */
class RadioactiveDecayEntropy extends URLRandomness {

	private static final String BASE_URL = "https://www.fourmilab.ch";

	/** The URL from which the random bytes are retrieved. */
	private static final String REQUEST_URL = BASE_URL
			+ "/cgi-bin/Hotbits?nbytes={0,number,0}&fmt=bin";

	/**
	 * http://www.fourmilab.ch/hotbits/ does not allow requests for more than
	 * 2048 bytes at once.
	 */
	static final int MAX_REQUEST_SIZE = 2048;

	@Override
	public final String toString() {
		return TRNG.HOTBITS.name();
	}

	@Override
	final int maximumRequest() {
		return MAX_REQUEST_SIZE;
	}

	@Override
	final void recieveBytes(ByteBuffer buffer, int requiredBytes)
			throws IOException {
		// System.out.println("toRead	" + requiredBytes);

		URL url = new URL(MessageFormat.format(REQUEST_URL, requiredBytes));
		ReadableByteChannel byteChannel = Channels.newChannel(url.openStream());

		try {
			byteChannel.read(buffer);
		} finally {
			byteChannel.close();
		}
	}

	@Override
	public final int minlen() {
		return MAX_REQUEST_SIZE;
	}

	@Override
	protected void uninstantiate() {
		// TODO Auto-generated method stub
		
	}

}
