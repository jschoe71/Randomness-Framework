/**
 * Randomness Framework combine the best-world practices of randomness
 * generation based on Channel API.
 * <p>
 * There are two fundamentally different strategies for generating random bits.
 * One strategy is to produce bits non-deterministically, where every bit of
 * output is based on a physical process that is unpredictable; this class of
 * random bit generators is commonly known as non-deterministic random bit
 * generators (NRBGs). The other strategy is to compute bits deterministically
 * using an algorithm; this class of RBGs is known as Deterministic Random Bit
 * Generators. <blockquote>
 * <table border=1 cellpadding=6 cellspacing=1  summary="Lists channels and their descriptions">
 * <tr>
 * <th>
 * <p align="center">
 * Randomness
 * </p>
 * </th>
 * <th>
 * <p align="center">
 * Description
 * </p>
 * </th>
 * </tr>
 * <tr>
 * <td>
 * <p align="left">
 * {@linkplain org.randomness.Randomness}
 * <td>
 * Define random number generator as a {@link java.nio.channels.Channel}
 * </tr>
 * <tr>
 * <td>
 * <p align="right">
 * {@linkplain org.randomness.Truerandomness}
 * <td>
 * Thiss class represents non-deterministic random bit generators as a True
 * Random Number Generators ({@linkplain org.randomness.TRNG}). This kind of generators uses
 * <i>entropy source</i> to obtain random bits and <i>extraction</i> function
 * which, when applied to a high-entropy source process generates a random
 * output that is shorter, yet uniformly distributed.
 * </tr>
 * <tr>
 * <td>
 * <p align="right">
 * {@linkplain org.randomness.Pseudorandomness}
 * <td>
 * This class represents pseudo random bit generator ({@linkplain org.randomness.PRNG}) which
 * compute bits repeatable, predictable and atomically using an underlying
 * deterministic <i>algorithm</i>. The output sequence is not true random, in
 * strong sense, but has all properties of true random sequence.
 * </tr>
 * <tr>
 * <td>
 * <p align="right">
 * {@linkplain org.randomness.Quasirandomess}
 * <td>
 * This class represents quasirandom analogue of a random process (
 * {@linkplain org.randomness.QRNG}) which is a deterministic process specifically designed so
 * that generated output give up serial independence of subsequently generated
 * values in order to obtain as uniform as possible coverage of the domain. This
 * avoids clusters and voids in the pattern of a finite set of selected points.
 * </tr>
 * </tr>
 * <tr>
 * <td>
 * <p align="right">
 * {@linkplain org.randomness.Cryptorandomness}
 * <td>
 * This class represents cryptographically secure pseudo-random number generator
 * ({@linkplain org.randomness.CSPRNG}) with properties that make it suitable for use in
 * cryptography. This generators has a unpredictable output, <i>security
 * strength</i> value, secret internal state and usually used as key, or
 * password generators. Specification inspired by NIST 800-90 special
 * publication.
 * </tr>
 * </table>
 * </blockquote>
 * 
 * <h3>Comparison of RNG's</h3>
 * 
 * <p>
 * The table below sums up the characteristics of the all types of random number
 * generators.
 * </p>
 * <blockquote>
 * <table border="1" cellpadding="6">
 * <tr>
 * <th></th>
 * <th>TRNG</th>
 * <th>PRNG</th>
 * <th>QRNG</th>
 * <th>CSPRNG</th>
 * 
 * </tr>
 * 
 * <tr>
 * <td>Efficiency</td>
 * <td class="center">Poor</td>
 * <td class="center">Excellent</td>
 * <td class="center">Excellent</td>
 * <td class="center">Medium</td>
 * </tr>
 * <tr>
 * <td>Determinism</td>
 * <td class="center">Nondeterministic</td>
 * <td class="center">Determinstic</td>
 * <td class="center">Determinstic</td>
 * <td class="center">Unpredictable</td>
 * </table>
 * </blockquote>
 * 
 * <hr width="80%">
 * <p>
 * Unless otherwise noted, passing a null argument to a constructor or method in
 * any class or interface in this package will cause a
 * {@link java.lang.NullPointerException} to be thrown.
 */
package org.randomness;

