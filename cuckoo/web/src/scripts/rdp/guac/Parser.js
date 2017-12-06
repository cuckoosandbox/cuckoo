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
 * Simple Guacamole protocol parser that invokes an oninstruction event when
 * full instructions are available from data received via receive().
 * 
 * @constructor
 */
Guacamole.Parser = function() {

    /**
     * Reference to this parser.
     * @private
     */
    var parser = this;

    /**
     * Current buffer of received data. This buffer grows until a full
     * element is available. After a full element is available, that element
     * is flushed into the element buffer.
     * 
     * @private
     */
    var buffer = "";

    /**
     * Buffer of all received, complete elements. After an entire instruction
     * is read, this buffer is flushed, and a new instruction begins.
     * 
     * @private
     */
    var element_buffer = [];

    // The location of the last element's terminator
    var element_end = -1;

    // Where to start the next length search or the next element
    var start_index = 0;

    /**
     * Appends the given instruction data packet to the internal buffer of
     * this Guacamole.Parser, executing all completed instructions at
     * the beginning of this buffer, if any.
     *
     * @param {String} packet The instruction data to receive.
     */
    this.receive = function(packet) {

        // Truncate buffer as necessary
        if (start_index > 4096 && element_end >= start_index) {

            buffer = buffer.substring(start_index);

            // Reset parse relative to truncation
            element_end -= start_index;
            start_index = 0;

        }

        // Append data to buffer
        buffer += packet;

        // While search is within currently received data
        while (element_end < buffer.length) {

            // If we are waiting for element data
            if (element_end >= start_index) {

                // We now have enough data for the element. Parse.
                var element = buffer.substring(start_index, element_end);
                var terminator = buffer.substring(element_end, element_end+1);

                // Add element to array
                element_buffer.push(element);

                // If last element, handle instruction
                if (terminator == ";") {

                    // Get opcode
                    var opcode = element_buffer.shift();

                    // Call instruction handler.
                    if (parser.oninstruction != null)
                        parser.oninstruction(opcode, element_buffer);

                    // Clear elements
                    element_buffer.length = 0;

                }
                else if (terminator != ',')
                    throw new Error("Illegal terminator.");

                // Start searching for length at character after
                // element terminator
                start_index = element_end + 1;

            }

            // Search for end of length
            var length_end = buffer.indexOf(".", start_index);
            if (length_end != -1) {

                // Parse length
                var length = parseInt(buffer.substring(element_end+1, length_end));
                if (length == NaN)
                    throw new Error("Non-numeric character in element length.");

                // Calculate start of element
                start_index = length_end + 1;

                // Calculate location of element terminator
                element_end = start_index + length;

            }
            
            // If no period yet, continue search when more data
            // is received
            else {
                start_index = buffer.length;
                break;
            }

        } // end parse loop

    };

    /**
     * Fired once for every complete Guacamole instruction received, in order.
     * 
     * @event
     * @param {String} opcode The Guacamole instruction opcode.
     * @param {Array} parameters The parameters provided for the instruction,
     *                           if any.
     */
    this.oninstruction = null;

};
