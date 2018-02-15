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
 * A reader which automatically handles the given input stream, returning
 * received blobs as a single data URI built over the course of the stream.
 * Note that this object will overwrite any installed event handlers on the
 * given Guacamole.InputStream.
 * 
 * @constructor
 * @param {Guacamole.InputStream} stream
 *     The stream that data will be read from.
 */
Guacamole.DataURIReader = function(stream, mimetype) {

    /**
     * Reference to this Guacamole.DataURIReader.
     * @private
     */
    var guac_reader = this;

    /**
     * Current data URI.
     *
     * @private
     * @type {String}
     */
    var uri = 'data:' + mimetype + ';base64,';

    // Receive blobs as array buffers
    stream.onblob = function dataURIReaderBlob(data) {

        // Currently assuming data will ALWAYS be safe to simply append. This
        // will not be true if the received base64 data encodes a number of
        // bytes that isn't a multiple of three (as base64 expands in a ratio
        // of exactly 3:4).
        uri += data;

    };

    // Simply call onend when end received
    stream.onend = function dataURIReaderEnd() {
        if (guac_reader.onend)
            guac_reader.onend();
    };

    /**
     * Returns the data URI of all data received through the underlying stream
     * thus far.
     *
     * @returns {String}
     *     The data URI of all data received through the underlying stream thus
     *     far.
     */
    this.getURI = function getURI() {
        return uri;
    };

    /**
     * Fired once this stream is finished and no further data will be written.
     *
     * @event
     */
    this.onend = null;

};