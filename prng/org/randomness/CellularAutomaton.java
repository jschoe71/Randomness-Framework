package org.randomness;

import java.nio.ByteBuffer;
import java.nio.DoubleBuffer;
import java.nio.FloatBuffer;
import java.nio.IntBuffer;
import java.nio.LongBuffer;
import java.util.Arrays;

/**
 * Java port of the <a
 * href="http://home.southernct.edu/~pasqualonia1/ca/report.html"
 * target="_top">cellular automaton pseudorandom number generator</a> developed
 * by Tony Pasqualoni.
 * 
 * @author Tony Pasqualoni (original C version)
 * @author Daniel Dyer (Java port - uncommons-math)
 * 
 */
final class CellularAutomaton extends PseudorandomnessEngine {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	private static final int[] RNG_RULE = { 100, 75, 16, 3, 229, 51, 197, 118,
			24, 62, 198, 11, 141, 152, 241, 188, 2, 17, 71, 47, 179, 177, 126,
			231, 202, 243, 59, 25, 77, 196, 30, 134, 199, 163, 34, 216, 21, 84,
			37, 182, 224, 186, 64, 79, 225, 45, 143, 20, 48, 147, 209, 221,
			125, 29, 99, 12, 46, 190, 102, 220, 80, 215, 242, 105, 15, 53, 0,
			67, 68, 69, 70, 89, 109, 195, 170, 78, 210, 131, 42, 110, 181, 145,
			40, 114, 254, 85, 107, 87, 72, 192, 90, 201, 162, 122, 86, 252, 94,
			129, 98, 132, 193, 249, 156, 172, 219, 230, 153, 54, 180, 151, 83,
			214, 123, 88, 164, 167, 116, 117, 7, 27, 23, 213, 235, 5, 65, 124,
			60, 127, 236, 149, 44, 28, 58, 121, 191, 13, 250, 10, 232, 112,
			101, 217, 183, 239, 8, 32, 228, 174, 49, 113, 247, 158, 106, 218,
			154, 66, 226, 157, 50, 26, 253, 93, 205, 41, 133, 165, 61, 161,
			187, 169, 6, 171, 81, 248, 56, 175, 246, 36, 178, 52, 57, 212, 39,
			176, 184, 185, 245, 63, 35, 189, 206, 76, 104, 233, 194, 19, 43,
			159, 108, 55, 200, 155, 14, 74, 244, 255, 222, 207, 208, 137, 128,
			135, 96, 144, 18, 95, 234, 139, 173, 92, 1, 203, 115, 223, 130, 97,
			91, 227, 146, 4, 31, 120, 211, 38, 22, 138, 140, 237, 238, 251,
			240, 160, 142, 119, 73, 103, 166, 33, 148, 9, 111, 136, 168, 150,
			82, 204, 100, 75, 16, 3, 229, 51, 197, 118, 24, 62, 198, 11, 141,
			152, 241, 188, 2, 17, 71, 47, 179, 177, 126, 231, 202, 243, 59, 25,
			77, 196, 30, 134, 199, 163, 34, 216, 21, 84, 37, 182, 224, 186, 64,
			79, 225, 45, 143, 20, 48, 147, 209, 221, 125, 29, 99, 12, 46, 190,
			102, 220, 80, 215, 242, 105, 15, 53, 0, 67, 68, 69, 70, 89, 109,
			195, 170, 78, 210, 131, 42, 110, 181, 145, 40, 114, 254, 85, 107,
			87, 72, 192, 90, 201, 162, 122, 86, 252, 94, 129, 98, 132, 193,
			249, 156, 172, 219, 230, 153, 54, 180, 151, 83, 214, 123, 88, 164,
			167, 116, 117, 7, 27, 23, 213, 235, 5, 65, 124, 60, 127, 236, 149,
			44, 28, 58, 121, 191, 13, 250, 10, 232, 112, 101, 217, 183, 239, 8,
			32, 228, 174, 49, 113, 247, 158, 106, 218, 154, 66, 226, 157, 50,
			26, 253, 93, 205, 41, 133, 165, 61, 161, 187, 169, 6, 171, 81, 248,
			56, 175, 246, 36, 178, 52, 57, 212, 39, 176, 184, 185, 245, 63, 35,
			189, 206, 76, 104, 233, 194, 19, 43, 159, 108, 55, 200, 155, 14,
			74, 244, 255, 222, 207, 208, 137, 128, 135, 96, 144, 18, 95, 234,
			139, 173, 92, 1, 203, 115, 223, 130, 97, 91, 227, 146, 4, 31, 120,
			211, 38, 22, 138, 140, 237, 238, 251, 240, 160, 142, 119, 73, 103,
			166, 33, 148, 9, 111, 136, 168, 150, 82 };

	private static final int AUTOMATON_LENGTH = 2056;

	// private final byte[] seed;
	private final int[] cells = new int[AUTOMATON_LENGTH];

	private int currentCellIndex = AUTOMATON_LENGTH - 1;

	public CellularAutomaton() {
		this.reset();
	}

	@Override
	protected final void instantiate(final ByteBuffer seed) {
		// //////////////// INSTANTIATE FUNCTION ////////////////////////
		Arrays.fill(cells, 0); // clear automata.

		currentCellIndex = AUTOMATON_LENGTH - 1;

		// Set initial cell states using seed.
		cells[AUTOMATON_LENGTH - 1] = seed.get() + 128;
		cells[AUTOMATON_LENGTH - 2] = seed.get() + 128;
		cells[AUTOMATON_LENGTH - 3] = seed.get() + 128;
		cells[AUTOMATON_LENGTH - 4] = seed.get() + 128;

		// we must create primitives very carefully seeding generator to
		// ensure that created the same primitives on all platform
		mark.clear();
		int seedAsInt = mark.getInt();

		if (seedAsInt != 0xFFFFFFFF) {
			seedAsInt++;
		}

		for (int i = 0; i < AUTOMATON_LENGTH - 4; i++) {
			cells[i] = 0x000000FF & (seedAsInt >> (i % 32));
		}

		// Evolve automaton before returning integers.
		for (int i = 0; i < AUTOMATON_LENGTH * AUTOMATON_LENGTH / 4; i++) {
			nextInt();
		}
		// //////////////// INSTANTIATE FUNCTION ////////////////////////
	}

	@Override
	public final int read(final ByteBuffer buffer) {
		final int numBytes = buffer.remaining();

		int bytes = 0;
		final int[] cells = this.cells;

		for (; (numBytes - bytes) >= INT_SIZE_BYTES;) {

			if (shared && !isOpen()) {// check interruption status
				return bytes; // interrupt
			}

			// ///////////////// GENERATE FUNCTION /////////////////////
			// Set cell addresses using address of current cell.
			final int cellC = currentCellIndex - 1;
			final int cellB = cellC - 1;
			final int cellA = cellB - 1;

			// Update cell states using rule table.
			cells[currentCellIndex] = RNG_RULE[cells[cellC]
					+ cells[currentCellIndex]];
			cells[cellC] = RNG_RULE[cells[cellB] + cells[cellC]];
			cells[cellB] = RNG_RULE[cells[cellA] + cells[cellB]];

			// Update the state of cellA and shift current cell to the
			// left by 4
			// bytes.
			if (cellA == 0) {
				cells[cellA] = RNG_RULE[cells[cellA]];
				currentCellIndex = AUTOMATON_LENGTH - 1;
			} else {
				cells[cellA] = RNG_RULE[cells[cellA - 1] + cells[cellA]];
				currentCellIndex -= 4;
			}

			// ///////////////// GENERATE FUNCTION /////////////////////
			buffer.putInt(convertCellsToInt(cells, cellA));
			bytes += INT_SIZE_BYTES; // inc bytes
		}

		if (bytes < numBytes) { // put last bytes

			final int rnd = generate32();

			for (int n = numBytes - bytes; n-- > 0; bytes++)
				buffer.put((byte) (rnd >>> (Byte.SIZE * n)));
		}

		return numBytes - buffer.remaining() /* should be zero */;
	}

	private final int generate32() {
		// ///////////////// GENERATE FUNCTION /////////////////////
		// Set cell addresses using address of current cell.
		final int cellC = currentCellIndex - 1;
		final int cellB = cellC - 1;
		final int cellA = cellB - 1;

		// Update cell states using rule table.
		cells[currentCellIndex] = RNG_RULE[cells[cellC]
				+ cells[currentCellIndex]];
		cells[cellC] = RNG_RULE[cells[cellB] + cells[cellC]];
		cells[cellB] = RNG_RULE[cells[cellA] + cells[cellB]];

		// Update the state of cellA and shift current cell to the
		// left by 4
		// bytes.
		if (cellA == 0) {
			cells[cellA] = RNG_RULE[cells[cellA]];
			currentCellIndex = AUTOMATON_LENGTH - 1;
		} else {
			cells[cellA] = RNG_RULE[cells[cellA - 1] + cells[cellA]];
			currentCellIndex -= 4;
		}

		// ///////////////// GENERATE FUNCTION /////////////////////
		return convertCellsToInt(cells, cellA);
	}

	@Override
	public final int read(final IntBuffer intBuffer) {

		final int numInts = intBuffer.remaining();
		final int[] cells = this.cells;

		int ints = 0;

		for (; ints < numInts;) {

			if (shared && !isOpen()) // check interruption status
				return ints; // interrupt

			// ///////////////// GENERATE FUNCTION /////////////////////
			// Set cell addresses using address of current cell.
			final int cellC = currentCellIndex - 1;
			final int cellB = cellC - 1;
			final int cellA = cellB - 1;

			// Update cell states using rule table.
			cells[currentCellIndex] = RNG_RULE[cells[cellC]
					+ cells[currentCellIndex]];
			cells[cellC] = RNG_RULE[cells[cellB] + cells[cellC]];
			cells[cellB] = RNG_RULE[cells[cellA] + cells[cellB]];

			// Update the state of cellA and shift current cell to the
			// left by 4
			// bytes.
			if (cellA == 0) {
				cells[cellA] = RNG_RULE[cells[cellA]];
				currentCellIndex = AUTOMATON_LENGTH - 1;
			} else {
				cells[cellA] = RNG_RULE[cells[cellA - 1] + cells[cellA]];
				currentCellIndex -= 4;
			}
			// ///////////////// GENERATE FUNCTION /////////////////////

			intBuffer.put(convertCellsToInt(cells, cellA));
			ints++;
		}

		return numInts - intBuffer.remaining();
	}

	@Override
	public final int read(final FloatBuffer floatBuffer) {

		final int numFloats = floatBuffer.remaining();

		int floats = 0;

		final int[] cells = this.cells;

		for (; floats < numFloats;) {

			if (shared && !isOpen()) // check interruption status
				return floats; // interrupt

			// ///////////////// GENERATE FUNCTION /////////////////////
			// Set cell addresses using address of current cell.
			final int cellC = currentCellIndex - 1;
			final int cellB = cellC - 1;
			final int cellA = cellB - 1;

			// Update cell states using rule table.
			cells[currentCellIndex] = RNG_RULE[cells[cellC]
					+ cells[currentCellIndex]];
			cells[cellC] = RNG_RULE[cells[cellB] + cells[cellC]];
			cells[cellB] = RNG_RULE[cells[cellA] + cells[cellB]];

			// Update the state of cellA and shift current cell to the
			// left by 4
			// bytes.
			if (cellA == 0) {
				cells[cellA] = RNG_RULE[cells[cellA]];
				currentCellIndex = AUTOMATON_LENGTH - 1;
			} else {
				cells[cellA] = RNG_RULE[cells[cellA - 1] + cells[cellA]];
				currentCellIndex -= 4;
			}
			// ///////////////// GENERATE FUNCTION /////////////////////

			floatBuffer.put((convertCellsToInt(cells, cellA) >>> 8)
					/ ((float) (1 << 24)));
			floats++;
		}

		return numFloats - floatBuffer.remaining();
	}

	@Override
	public final int read(final LongBuffer longBuffer) {

		final int numLongs = longBuffer.remaining();

		final int[] cells = this.cells;

		for (int longs = 0; longs < numLongs;) {

			if (shared && !isOpen()) // check interruption status
				return longs; // interrupt

			int l;
			int r;

			// ///////////////// GENERATE FUNCTION /////////////////////
			// Set cell addresses using address of current cell.
			int cellC = currentCellIndex - 1;
			int cellB = cellC - 1;
			int cellA = cellB - 1;

			// Update cell states using rule table.
			cells[currentCellIndex] = RNG_RULE[cells[cellC]
					+ cells[currentCellIndex]];
			cells[cellC] = RNG_RULE[cells[cellB] + cells[cellC]];
			cells[cellB] = RNG_RULE[cells[cellA] + cells[cellB]];

			// Update the state of cellA and shift current cell to the
			// left by 4
			// bytes.
			if (cellA == 0) {
				cells[cellA] = RNG_RULE[cells[cellA]];
				currentCellIndex = AUTOMATON_LENGTH - 1;
			} else {
				cells[cellA] = RNG_RULE[cells[cellA - 1] + cells[cellA]];
				currentCellIndex -= 4;
			}
			// LEFT WORD
			l = convertCellsToInt(cells, cellA);

			// Set cell addresses using address of current cell.
			cellC = currentCellIndex - 1;
			cellB = cellC - 1;
			cellA = cellB - 1;

			// Update cell states using rule table.
			cells[currentCellIndex] = RNG_RULE[cells[cellC]
					+ cells[currentCellIndex]];
			cells[cellC] = RNG_RULE[cells[cellB] + cells[cellC]];
			cells[cellB] = RNG_RULE[cells[cellA] + cells[cellB]];

			// Update the state of cellA and shift current cell to the
			// left by 4
			// bytes.
			if (cellA == 0) {
				cells[cellA] = RNG_RULE[cells[cellA]];
				currentCellIndex = AUTOMATON_LENGTH - 1;
			} else {
				cells[cellA] = RNG_RULE[cells[cellA - 1] + cells[cellA]];
				currentCellIndex -= 4;
			}

			// RIGHT WORD
			r = convertCellsToInt(cells, cellA);

			longBuffer.put((((long) l) << 32) + r);
			longs++;
		}

		return numLongs - longBuffer.remaining();
	}

	@Override
	public final int read(final DoubleBuffer doubleBuffer) {

		final int numDoubles = doubleBuffer.remaining();

		int doubles = 0;
		final int[] cells = this.cells;

		for (; doubles < numDoubles;) {

			if (shared && !isOpen()) // check interruption status
				return doubles; // interrupt

			int l;
			int r;

			// ///////////////// GENERATE FUNCTION /////////////////////
			// Set cell addresses using address of current cell.
			int cellC = currentCellIndex - 1;
			int cellB = cellC - 1;
			int cellA = cellB - 1;

			// Update cell states using rule table.
			cells[currentCellIndex] = RNG_RULE[cells[cellC]
					+ cells[currentCellIndex]];
			cells[cellC] = RNG_RULE[cells[cellB] + cells[cellC]];
			cells[cellB] = RNG_RULE[cells[cellA] + cells[cellB]];

			// Update the state of cellA and shift current cell to the
			// left by 4
			// bytes.
			if (cellA == 0) {
				cells[cellA] = RNG_RULE[cells[cellA]];
				currentCellIndex = AUTOMATON_LENGTH - 1;
			} else {
				cells[cellA] = RNG_RULE[cells[cellA - 1] + cells[cellA]];
				currentCellIndex -= 4;
			}
			// LEFT WORD
			l = convertCellsToInt(cells, cellA);

			// Set cell addresses using address of current cell.
			cellC = currentCellIndex - 1;
			cellB = cellC - 1;
			cellA = cellB - 1;

			// Update cell states using rule table.
			cells[currentCellIndex] = RNG_RULE[cells[cellC]
					+ cells[currentCellIndex]];
			cells[cellC] = RNG_RULE[cells[cellB] + cells[cellC]];
			cells[cellB] = RNG_RULE[cells[cellA] + cells[cellB]];

			// Update the state of cellA and shift current cell to the
			// left by 4
			// bytes.
			if (cellA == 0) {
				cells[cellA] = RNG_RULE[cells[cellA]];
				currentCellIndex = AUTOMATON_LENGTH - 1;
			} else {
				cells[cellA] = RNG_RULE[cells[cellA - 1] + cells[cellA]];
				currentCellIndex -= 4;
			}

			// RIGHT WORD
			r = convertCellsToInt(cells, cellA);

			doubleBuffer.put(((((long) (l >>> 6)) << 27) + (r >>> 5))
					/ (double) (1L << 53));
			doubles++;
		}

		return numDoubles - doubleBuffer.remaining() /* should be zero */;
	}

	@Override
	public final int nextInt() {
		// Set cell addresses using address of current cell.
		final int cellC = currentCellIndex - 1;
		final int cellB = cellC - 1;
		final int cellA = cellB - 1;

		final int[] cells = this.cells;
		// Update cell states using rule table.
		cells[currentCellIndex] = RNG_RULE[cells[cellC]
				+ cells[currentCellIndex]];
		cells[cellC] = RNG_RULE[cells[cellB] + cells[cellC]];
		cells[cellB] = RNG_RULE[cells[cellA] + cells[cellB]];

		// Update the state of cellA and shift current cell to the left by 4
		// bytes.
		if (cellA == 0) {
			cells[cellA] = RNG_RULE[cells[cellA]];
			currentCellIndex = AUTOMATON_LENGTH - 1;
		} else {
			cells[cellA] = RNG_RULE[cells[cellA - 1] + cells[cellA]];
			currentCellIndex -= 4;
		}

		return convertCellsToInt(cells, cellA);
	}

	@Override
	public final float nextFloat() {
		// Set cell addresses using address of current cell.
		final int cellC = currentCellIndex - 1;
		final int cellB = cellC - 1;
		final int cellA = cellB - 1;

		final int[] cells = this.cells;

		// Update cell states using rule table.
		cells[currentCellIndex] = RNG_RULE[cells[cellC]
				+ cells[currentCellIndex]];
		cells[cellC] = RNG_RULE[cells[cellB] + cells[cellC]];
		cells[cellB] = RNG_RULE[cells[cellA] + cells[cellB]];

		// Update the state of cellA and shift current cell to the
		// left by 4
		// bytes.
		if (cellA == 0) {
			cells[cellA] = RNG_RULE[cells[cellA]];
			currentCellIndex = AUTOMATON_LENGTH - 1;
		} else {
			cells[cellA] = RNG_RULE[cells[cellA - 1] + cells[cellA]];
			currentCellIndex -= 4;
		}
		// ///////////////// GENERATE FUNCTION /////////////////////

		return ((convertCellsToInt(cells, cellA) >>> 8) / ((float) (1 << 24)));
	}

	@Override
	public final long nextLong() {
		int l;
		int r;

		// ///////////////// GENERATE FUNCTION /////////////////////
		// Set cell addresses using address of current cell.
		int cellC = currentCellIndex - 1;
		int cellB = cellC - 1;
		int cellA = cellB - 1;

		final int[] cells = this.cells;

		// Update cell states using rule table.
		cells[currentCellIndex] = RNG_RULE[cells[cellC]
				+ cells[currentCellIndex]];
		cells[cellC] = RNG_RULE[cells[cellB] + cells[cellC]];
		cells[cellB] = RNG_RULE[cells[cellA] + cells[cellB]];

		// Update the state of cellA and shift current cell to the
		// left by 4
		// bytes.
		if (cellA == 0) {
			cells[cellA] = RNG_RULE[cells[cellA]];
			currentCellIndex = AUTOMATON_LENGTH - 1;
		} else {
			cells[cellA] = RNG_RULE[cells[cellA - 1] + cells[cellA]];
			currentCellIndex -= 4;
		}
		// LEFT WORD
		l = convertCellsToInt(cells, cellA);

		// Set cell addresses using address of current cell.
		cellC = currentCellIndex - 1;
		cellB = cellC - 1;
		cellA = cellB - 1;

		// Update cell states using rule table.
		cells[currentCellIndex] = RNG_RULE[cells[cellC]
				+ cells[currentCellIndex]];
		cells[cellC] = RNG_RULE[cells[cellB] + cells[cellC]];
		cells[cellB] = RNG_RULE[cells[cellA] + cells[cellB]];

		// Update the state of cellA and shift current cell to the
		// left by 4
		// bytes.
		if (cellA == 0) {
			cells[cellA] = RNG_RULE[cells[cellA]];
			currentCellIndex = AUTOMATON_LENGTH - 1;
		} else {
			cells[cellA] = RNG_RULE[cells[cellA - 1] + cells[cellA]];
			currentCellIndex -= 4;
		}

		// RIGHT WORD
		r = convertCellsToInt(cells, cellA);

		return (((long) l) << 32) + r;
	}

	private static int convertCellsToInt(final int[] cells, final int offset) {
		return cells[offset] + (cells[offset + 1] << 8)
				+ (cells[offset + 2] << 16) + (cells[offset + 3] << 24);
	}

	@Override
	public final String toString() {
		return PRNG.CELLULAR_AUTOMATON.name();
	}

	@Override
	public final int minlen() {
		return INT_SIZE_BYTES;
	}

	@Override
	public final int hashCode() {
		if (!isOpen())
			return System.identityHashCode(this);
		
		int hash = 17;
		hash += 31 * hash + Arrays.hashCode(cells);
		hash += 31 * hash + currentCellIndex;

		return hash;
	}

	@Override
	public final boolean equals(final Object obj) {

		if (obj == null)
			return false;

		if (!this.isOpen())
			return false;

		if (obj == this)
			return true;

		if (!(obj instanceof CellularAutomaton))
			return false;

		final CellularAutomaton that = (CellularAutomaton) obj;

		if (!that.isOpen())
			return false;

		return this.currentCellIndex == that.currentCellIndex
				&& Arrays.equals(this.cells, that.cells);
	}

	@Override
	public final CellularAutomaton copy() {
		final CellularAutomaton copy = new CellularAutomaton();
		copy.reseed((ByteBuffer) this.mark.clear());
		copy.currentCellIndex = this.currentCellIndex;
		System.arraycopy(this.cells, 0, copy.cells, 0, this.cells.length);

		return copy;
	}
}
