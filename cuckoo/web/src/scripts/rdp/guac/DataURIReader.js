/*
 * Copyright (C) 2015 Glyptodon LLC
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