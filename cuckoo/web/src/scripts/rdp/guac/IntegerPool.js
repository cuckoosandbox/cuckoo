/*
 * Copyright (C) 2013 Glyptodon LLC
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

var Guacamole = Guacamole || {};

/**
 * Integer pool which returns consistently increasing integers while integers
 * are in use, and previously-used integers when possible.
 * @constructor 
 */
Guacamole.IntegerPool = function() {

    /**
     * Reference to this integer pool.
     *
     * @private
     */
    var guac_pool = this;

    /**
     * Array of available integers.
     *
     * @private
     * @type {Number[]}
     */
    var pool = [];

    /**
     * The next integer to return if no more integers remain.
     * @type {Number}
     */
    this.next_int = 0;

    /**
     * Returns the next available integer in the pool. If possible, a previously
     * used integer will be returned.
     * 
     * @return {Number} The next available integer.
     */
    this.next = function() {

        // If free'd integers exist, return one of those
        if (pool.length > 0)
            return pool.shift();

        // Otherwise, return a new integer
        return guac_pool.next_int++;

    };

    /**
     * Frees the given integer, allowing it to be reused.
     * 
     * @param {Number} integer The integer to free.
     */
    this.free = function(integer) {
        pool.push(integer);
    };

};
