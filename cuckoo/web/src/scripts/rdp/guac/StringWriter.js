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
 * A writer which automatically writes to the given output stream with text
 * data.
 * 
 * @constructor
 * @param {Guacamole.OutputStream} stream The stream that data will be written
 *                                        to.
 */
Guacamole.StringWriter = function(stream) {

    /**
     * Reference to this Guacamole.StringWriter.
     * @private
     */
    var guac_writer = this;

    /**
     * Wrapped Guacamole.ArrayBufferWriter.
     * @private
     * @type {Guacamole.ArrayBufferWriter}
     */
    var array_writer = new Guacamole.ArrayBufferWriter(stream);

    /**
     * Internal buffer for UTF-8 output.
     * @private
     */
    var buffer = new Uint8Array(8192);

    /**
     * The number of bytes currently in the buffer.
     * @private
     */
    var length = 0;

    // Simply call onack for acknowledgements
    array_writer.onack = function(status) {
        if (guac_writer.onack)
            guac_writer.onack(status);
    };

    /**
     * Expands the size of the underlying buffer by the given number of bytes,
     * updating the length appropriately.
     * 
     * @private
     * @param {Number} bytes The number of bytes to add to the underlying
     *                       buffer.
     */
    function __expand(bytes) {

        // Resize buffer if more space needed
        if (length+bytes >= buffer.length) {
            var new_buffer = new Uint8Array((length+bytes)*2);
            new_buffer.set(buffer);
            buffer = new_buffer;
        }

        length += bytes;

    }

    /**
     * Appends a single Unicode character to the current buffer, resizing the
     * buffer if necessary. The character will be encoded as UTF-8.
     * 
     * @private
     * @param {Number} codepoint The codepoint of the Unicode character to
     *                           append.
     */
    function __append_utf8(codepoint) {

        var mask;
        var bytes;

        // 1 byte
        if (codepoint <= 0x7F) {
            mask = 0x00;
            bytes = 1;
        }

        // 2 byte
        else if (codepoint <= 0x7FF) {
            mask = 0xC0;
            bytes = 2;
        }

        // 3 byte
        else if (codepoint <= 0xFFFF) {
            mask = 0xE0;
            bytes = 3;
        }

        // 4 byte
        else if (codepoint <= 0x1FFFFF) {
            mask = 0xF0;
            bytes = 4;
        }

        // If invalid codepoint, append replacement character
        else {
            __append_utf8(0xFFFD);
            return;
        }

        // Offset buffer by size
        __expand(bytes);
        var offset = length - 1;

        // Add trailing bytes, if any
        for (var i=1; i<bytes; i++) {
            buffer[offset--] = 0x80 | (codepoint & 0x3F);
            codepoint >>= 6;
        }

        // Set initial byte
        buffer[offset] = mask | codepoint;

    }

    /**
     * Encodes the given string as UTF-8, returning an ArrayBuffer containing
     * the resulting bytes.
     * 
     * @private
     * @param {String} text The string to encode as UTF-8.
     * @return {Uint8Array} The encoded UTF-8 data.
     */
    function __encode_utf8(text) {

        // Fill buffer with UTF-8
        for (var i=0; i<text.length; i++) {
            var codepoint = text.charCodeAt(i);
            __append_utf8(codepoint);
        }

        // Flush buffer
        if (length > 0) {
            var out_buffer = buffer.subarray(0, length);
            length = 0;
            return out_buffer;
        }

    }

    /**
     * Sends the given text.
     * 
     * @param {String} text The text to send.
     */
    this.sendText = function(text) {
        array_writer.sendData(__encode_utf8(text));
    };

    /**
     * Signals that no further text will be sent, effectively closing the
     * stream.
     */
    this.sendEnd = function() {
        array_writer.sendEnd();
    };

    /**
     * Fired for received data, if acknowledged by the server.
     * @event
     * @param {Guacamole.Status} status The status of the operation.
     */
    this.onack = null;

};