package org.randomness;

/**
 * Interface contains type definitions of various Pseudorandom Engines and its
 * states (scaffolding type).
 * 
 * @author Anton Kabysh
 * 
 */
interface Engine {
	/**
	 * Represents Linear Congruental Generator with 64 bit state;
	 */
	interface LCG64 {
		long seed();
	}

	/**
	 * Indicate Mersenne Twister generators family.
	 * 
	 */
	interface MT {
		int mti();

		Object mt();

		Object mag01();
	}

	/**
	 * Indicate SIMD-oriented Fast Mersenne Twister generators family.
	 * 
	 */
	interface SFMT {

		int idx();

		int[] sfmt();
	}
}
