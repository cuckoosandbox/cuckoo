/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
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
