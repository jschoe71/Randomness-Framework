package org.randomness;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URL;
import java.nio.ByteBuffer;
import java.text.MessageFormat;
import java.util.Arrays;

/**
 * Connects to the <a href="http://www.random.org" target="_top">random.org</a>
 * website (via HTTPS) and downloads a set of random bits generated by
 * atmosferic noise. It is generally better to use the
 * {@linkplain TRNG#DEV_RANDOM} where possible, as it should be much quicker.
 * This seed generator is most useful on Microsoft Windows and other platforms
 * that do not provide {@literal /dev/random}.
 * 
 * @author Daniel Dyer (original uncommons-math RandomDotOrgSeedGenerator)
 * @author Anton Kabysh (adopted version)
 */
class AtmosfericNoiseEntropy extends URLRandomness {

	private static final String BASE_URL = "https://www.random.org";

	/** The URL from which the random bytes are retrieved. */
	private static final String REQUEST_URL = BASE_URL
			+ "/integers/?num={0,number,0}&min=0&max=255&col=1&base=16&format=plain&rnd=new";

	/** Random.org does not allow requests for more than 10k integers at once. */
	static final int MAX_REQUEST_SIZE = 10000;

	AtmosfericNoiseEntropy() {
	}

	@Override
	final int maximumRequest() {
		return MAX_REQUEST_SIZE;
	}

	/**
	 * Connects and receive random bytes from random.org via https.
	 * 
	 * @param buffer
	 *            a buffer to receive bytes from random.org.
	 * @param requiredBytes
	 *            The preferred number of bytes to request from random.org.
	 * @throws IOException
	 *             If there is a problem downloading the random bits.
	 */
	@Override
	void recieveBytes(ByteBuffer buffer, int requiredBytes) throws IOException {
		// TODO more efficient ?
		// from 0 to 255, one column, base=16, numbers - specified
		URL url = new URL(MessageFormat.format(REQUEST_URL, requiredBytes));
		BufferedReader reader = new BufferedReader(new InputStreamReader(
				url.openStream()));

		try { // parse input
			for (String line = reader.readLine(); line != null; line = reader
					.readLine()) {
				buffer.put((byte) Integer.parseInt(line, 16));
			}
		} finally {
			reader.close();
		}
	}

	@Override
	public final String toString() {
		return TRNG.RANDOM_ORG.name();
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
