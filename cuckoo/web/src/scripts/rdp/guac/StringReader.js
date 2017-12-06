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
 * strictly text data. Note that this object will overwrite any installed event
 * handlers on the given Guacamole.InputStream.
 * 
 * @constructor
 * @param {Guacamole.InputStream} stream The stream that data will be read
 *                                       from.
 */
Guacamole.StringReader = function(stream) {

    /**
     * Reference to this Guacamole.InputStream.
     * @private
     */
    var guac_reader = this;

    /**
     * Wrapped Guacamole.ArrayBufferReader.
     * @private
     * @type {Guacamole.ArrayBufferReader}
     */
    var array_reader = new Guacamole.ArrayBufferReader(stream);

    /**
     * The number of bytes remaining for the current codepoint.
     *
     * @private
     * @type {Number}
     */
    var bytes_remaining = 0;

    /**
     * The current codepoint value, as calculated from bytes read so far.
     *
     * @private
     * @type {Number}
     */
    var codepoint = 0;

    /**
     * Decodes the given UTF-8 data into a Unicode string. The data may end in
     * the middle of a multibyte character.
     * 
     * @private
     * @param {ArrayBuffer} buffer Arbitrary UTF-8 data.
     * @return {String} A decoded Unicode string.
     */
    function __decode_utf8(buffer) {

        var text = "";

        var bytes = new Uint8Array(buffer);
        for (var i=0; i<bytes.length; i++) {

            // Get current byte
            var value = bytes[i];

            // Start new codepoint if nothing yet read
            if (bytes_remaining === 0) {

                // 1 byte (0xxxxxxx)
                if ((value | 0x7F) === 0x7F)
                    text += String.fromCharCode(value);

                // 2 byte (110xxxxx)
                else if ((value | 0x1F) === 0xDF) {
                    codepoint = value & 0x1F;
                    bytes_remaining = 1;
                }

                // 3 byte (1110xxxx)
                else if ((value | 0x0F )=== 0xEF) {
                    codepoint = value & 0x0F;
                    bytes_remaining = 2;
                }

                // 4 byte (11110xxx)
                else if ((value | 0x07) === 0xF7) {
                    codepoint = value & 0x07;
                    bytes_remaining = 3;
                }

                // Invalid byte
                else
                    text += "\uFFFD";

            }

            // Continue existing codepoint (10xxxxxx)
            else if ((value | 0x3F) === 0xBF) {

                codepoint = (codepoint << 6) | (value & 0x3F);
                bytes_remaining--;

                // Write codepoint if finished
                if (bytes_remaining === 0)
                    text += String.fromCharCode(codepoint);

            }

            // Invalid byte
            else {
                bytes_remaining = 0;
                text += "\uFFFD";
            }

        }

        return text;

    }

    // Receive blobs as strings
    array_reader.ondata = function(buffer) {

        // Decode UTF-8
        var text = __decode_utf8(buffer);

        // Call handler, if present
        if (guac_reader.ontext)
            guac_reader.ontext(text);

    };

    // Simply call onend when end received
    array_reader.onend = function() {
        if (guac_reader.onend)
            guac_reader.onend();
    };

    /**
     * Fired once for every blob of text data received.
     * 
     * @event
     * @param {String} text The data packet received.
     */
    this.ontext = null;

    /**
     * Fired once this stream is finished and no further data will be written.
     * @event
     */
    this.onend = null;

};