package org.randomness;

import java.security.SecureRandom;
import java.security.SecureRandomSpi;

/**
 * Used to have acess to protected constructor with SecureRandomSpi.
 * 
 * @author Anton Kabysh
 * 
 */
final class RandomEngine extends SecureRandom {

	SecureRandomSpi engine;

	public RandomEngine(SecureRandomSpi engine) {
		super(engine, null);
		this.engine = engine;
	}

	@Override
	public final int hashCode() {
		return engine.hashCode();
	}

	@Override
	public final boolean equals(Object obj) {
		if (!(obj instanceof RandomEngine))
			return false;

		if (obj == this)
			return true;

		RandomEngine that = (RandomEngine) obj;
		// test engines internal states and verify consistency hashCode
		return this.engine.equals(that.engine) ? this.engine.hashCode() == that.engine
				.hashCode() : false;
	}

	@Override
	public final String getAlgorithm() {
		final String algorithm = engine.toString();
		return (algorithm != null) ? algorithm : "unknown";
	}

	@Override
	public final String toString() {
		return getAlgorithm();
	}
}