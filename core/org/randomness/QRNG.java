package org.randomness;

import java.util.Random;

/**
 * List of implemented <i>Quasi-Random Number Generators</i> produce highly
 * uniform samples of the unit hypercube. <br>
 * <h3 align="center"><i>PROVISIONAL API, WORK IN PROGRESS</i></h3>
 * <p>
 * QRNGs minimize the discrepancy between the distribution of generated points
 * and a distribution with equal proportions of points in each sub-cube of a
 * uniform partition of the hypercube. As a result, QRNGs systematically fill
 * the "holes" in any initial segment of the generated quasi-random sequence.
 * <p>
 * Unlike the pseudorandom sequences described in Common Generation Methods,
 * quasi-random sequences fail many statistical tests for randomness.
 * Approximating true randomness, however, is not their goal. Quasi-random
 * sequences seek to fill space uniformly, and to do so in such a way that
 * initial segments approximate this behavior up to a specified density.
 * <p>
 * QRNG applications include:
 * <ul>
 * <li>
 * <b>Quasi-Monte Carlo (QMC) integration</b>. Monte Carlo techniques are often
 * used to evaluate difficult, multi-dimensional integrals without a closed-form
 * solution. QMC uses quasi-random sequences to improve the convergence
 * properties of these techniques.
 * <li>
 * <i>Space-filling experimental designs</i>. In many experimental settings,
 * taking measurements at every factor setting is expensive or infeasible.
 * Quasi-random sequences provide efficient, uniform sampling of the design
 * space.
 * <li>
 * <i>Global optimization</i>. Optimization algorithms typically find a local
 * optimum in the neighborhood of an initial value. By using a quasi-random
 * sequence of initial values, searches for global optima uniformly sample the
 * basins of attraction of all local minima.
 * <li>
 * Such a sequence is extremely useful in computational problems where numbers
 * are computed on a grid, but it is not known in advance how fine the grid must
 * be to obtain accurate results. Using a quasirandom sequence allows stopping
 * at any point where convergence is observed, whereas the usual approach of
 * halving the interval between subsequent computations requires a huge number
 * of computations between stopping points.
 * </ul>
 * 
 * 
 * 
 * 
 * @author Антон
 * 
 */
public enum QRNG {

	HALTON, SOBOL, LATINE_HYPERCUBE;
	public static void main(String[] args) {
		Random random;
	}
}
