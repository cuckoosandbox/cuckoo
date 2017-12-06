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
 * Guacamole protocol client. Given a {@link Guacamole.Tunnel},
 * automatically handles incoming and outgoing Guacamole instructions via the
 * provided tunnel, updating its display using one or more canvas elements.
 * 
 * @constructor
 * @param {Guacamole.Tunnel} tunnel The tunnel to use to send and receive
 *                                  Guacamole instructions.
 */
Guacamole.Client = function(tunnel) {

    var guac_client = this;

    var STATE_IDLE          = 0;
    var STATE_CONNECTING    = 1;
    var STATE_WAITING       = 2;
    var STATE_CONNECTED     = 3;
    var STATE_DISCONNECTING = 4;
    var STATE_DISCONNECTED  = 5;

    var currentState = STATE_IDLE;
    
    var currentTimestamp = 0;
    var pingInterval = null;

    /**
     * Translation from Guacamole protocol line caps to Layer line caps.
     * @private
     */
    var lineCap = {
        0: "butt",
        1: "round",
        2: "square"
    };

    /**
     * Translation from Guacamole protocol line caps to Layer line caps.
     * @private
     */
    var lineJoin = {
        0: "bevel",
        1: "miter",
        2: "round"
    };

    /**
     * The underlying Guacamole display.
     *
     * @private
     * @type {Guacamole.Display}
     */
    var display = new Guacamole.Display();

    /**
     * All available layers and buffers
     *
     * @private
     * @type {Object.<Number, (Guacamole.Display.VisibleLayer|Guacamole.Layer)>}
     */
    var layers = {};
    
    /**
     * All audio players currently in use by the client. Initially, this will
     * be empty, but audio players may be allocated by the server upon request.
     *
     * @private
     * @type {Object.<Number, Guacamole.AudioPlayer>}
     */
    var audioPlayers = {};

    /**
     * All video players currently in use by the client. Initially, this will
     * be empty, but video players may be allocated by the server upon request.
     *
     * @private
     * @type {Object.<Number, Guacamole.VideoPlayer>}
     */
    var videoPlayers = {};

    // No initial parsers
    var parsers = [];

    // No initial streams 
    var streams = [];

    /**
     * All current objects. The index of each object is dictated by the
     * Guacamole server.
     *
     * @private
     * @type {Guacamole.Object[]}
     */
    var objects = [];

    // Pool of available stream indices
    var stream_indices = new Guacamole.IntegerPool();

    // Array of allocated output streams by index
    var output_streams = [];

    function setState(state) {
        if (state != currentState) {
            currentState = state;
            if (guac_client.onstatechange)
                guac_client.onstatechange(currentState);
        }
    }

    function isConnected() {
        return currentState == STATE_CONNECTED
            || currentState == STATE_WAITING;
    }

    /**
     * Returns the underlying display of this Guacamole.Client. The display
     * contains an Element which can be added to the DOM, causing the
     * display to become visible.
     * 
     * @return {Guacamole.Display} The underlying display of this
     *                             Guacamole.Client.
     */
    this.getDisplay = function() {
        return display;
    };

    /**
     * Sends the current size of the screen.
     * 
     * @param {Number} width The width of the screen.
     * @param {Number} height The height of the screen.
     */
    this.sendSize = function(width, height) {

        // Do not send requests if not connected
        if (!isConnected())
            return;

        tunnel.sendMessage("size", width, height);

    };

    /**
     * Sends a key event having the given properties as if the user
     * pressed or released a key.
     * 
     * @param {Boolean} pressed Whether the key is pressed (true) or released
     *                          (false).
     * @param {Number} keysym The keysym of the key being pressed or released.
     */
    this.sendKeyEvent = function(pressed, keysym) {
        // Do not send requests if not connected
        if (!isConnected())
            return;

        tunnel.sendMessage("key", keysym, pressed);
    };

    /**
     * Sends a mouse event having the properties provided by the given mouse
     * state.
     * 
     * @param {Guacamole.Mouse.State} mouseState The state of the mouse to send
     *                                           in the mouse event.
     */
    this.sendMouseState = function(mouseState) {

        // Do not send requests if not connected
        if (!isConnected())
            return;

        // Update client-side cursor
        display.moveCursor(
            Math.floor(mouseState.x),
            Math.floor(mouseState.y)
        );

        // Build mask
        var buttonMask = 0;
        if (mouseState.left)   buttonMask |= 1;
        if (mouseState.middle) buttonMask |= 2;
        if (mouseState.right)  buttonMask |= 4;
        if (mouseState.up)     buttonMask |= 8;
        if (mouseState.down)   buttonMask |= 16;

        // Send message
        tunnel.sendMessage("mouse", Math.floor(mouseState.x), Math.floor(mouseState.y), buttonMask);
    };

    /**
     * Sets the clipboard of the remote client to the given text data.
     *
     * @deprecated Use createClipboardStream() instead. 
     * @param {String} data The data to send as the clipboard contents.
     */
    this.setClipboard = function(data) {

        // Do not send requests if not connected
        if (!isConnected())
            return;

        // Open stream
        var stream = guac_client.createClipboardStream("text/plain");
        var writer = new Guacamole.StringWriter(stream);

        // Send text chunks
        for (var i=0; i<data.length; i += 4096)
            writer.sendText(data.substring(i, i+4096));

        // Close stream
        writer.sendEnd();

    };

    /**
     * Opens a new file for writing, having the given index, mimetype and
     * filename.
     * 
     * @param {String} mimetype The mimetype of the file being sent.
     * @param {String} filename The filename of the file being sent.
     * @return {Guacamole.OutputStream} The created file stream.
     */
    this.createFileStream = function(mimetype, filename) {

        // Allocate index
        var index = stream_indices.next();

        // Create new stream
        tunnel.sendMessage("file", index, mimetype, filename);
        var stream = output_streams[index] = new Guacamole.OutputStream(guac_client, index);

        // Override sendEnd() of stream to automatically free index
        var old_end = stream.sendEnd;
        stream.sendEnd = function() {
            old_end();
            stream_indices.free(index);
            delete output_streams[index];
        };

        // Return new, overridden stream
        return stream;

    };

    /**
     * Opens a new pipe for writing, having the given name and mimetype. 
     * 
     * @param {String} mimetype The mimetype of the data being sent.
     * @param {String} name The name of the pipe.
     * @return {Guacamole.OutputStream} The created file stream.
     */
    this.createPipeStream = function(mimetype, name) {

        // Allocate index
        var index = stream_indices.next();

        // Create new stream
        tunnel.sendMessage("pipe", index, mimetype, name);
        var stream = output_streams[index] = new Guacamole.OutputStream(guac_client, index);

        // Override sendEnd() of stream to automatically free index
        var old_end = stream.sendEnd;
        stream.sendEnd = function() {
            old_end();
            stream_indices.free(index);
            delete output_streams[index];
        };

        // Return new, overridden stream
        return stream;

    };

    /**
     * Opens a new clipboard object for writing, having the given mimetype.
     * 
     * @param {String} mimetype The mimetype of the data being sent.
     * @param {String} name The name of the pipe.
     * @return {Guacamole.OutputStream} The created file stream.
     */
    this.createClipboardStream = function(mimetype) {

        // Allocate index
        var index = stream_indices.next();

        // Create new stream
        tunnel.sendMessage("clipboard", index, mimetype);
        var stream = output_streams[index] = new Guacamole.OutputStream(guac_client, index);

        // Override sendEnd() of stream to automatically free index
        var old_end = stream.sendEnd;
        stream.sendEnd = function() {
            old_end();
            stream_indices.free(index);
            delete output_streams[index];
        };

        // Return new, overridden stream
        return stream;

    };

    /**
     * Creates a new output stream associated with the given object and having
     * the given mimetype and name. The legality of a mimetype and name is
     * dictated by the object itself.
     *
     * @param {Number} index
     *     The index of the object for which the output stream is being
     *     created.
     *
     * @param {String} mimetype
     *     The mimetype of the data which will be sent to the output stream.
     *
     * @param {String} name
     *     The defined name of an output stream within the given object.
     *
     * @returns {Guacamole.OutputStream}
     *     An output stream which will write blobs to the named output stream
     *     of the given object.
     */
    this.createObjectOutputStream = function createObjectOutputStream(index, mimetype, name) {

        // Allocate index
        var streamIndex = stream_indices.next();

        // Create new stream
        tunnel.sendMessage("put", index, streamIndex, mimetype, name);
        var stream = output_streams[streamIndex] = new Guacamole.OutputStream(guac_client, streamIndex);

        // Override sendEnd() of stream to automatically free index
        var oldEnd = stream.sendEnd;
        stream.sendEnd = function freeStreamIndex() {
            oldEnd();
            stream_indices.free(streamIndex);
            delete output_streams[streamIndex];
        };

        // Return new, overridden stream
        return stream;

    };

    /**
     * Requests read access to the input stream having the given name. If
     * successful, a new input stream will be created.
     *
     * @param {Number} index
     *     The index of the object from which the input stream is being
     *     requested.
     *
     * @param {String} name
     *     The name of the input stream to request.
     */
    this.requestObjectInputStream = function requestObjectInputStream(index, name) {

        // Do not send requests if not connected
        if (!isConnected())
            return;

        tunnel.sendMessage("get", index, name);
    };

    /**
     * Acknowledge receipt of a blob on the stream with the given index.
     * 
     * @param {Number} index The index of the stream associated with the
     *                       received blob.
     * @param {String} message A human-readable message describing the error
     *                         or status.
     * @param {Number} code The error code, if any, or 0 for success.
     */
    this.sendAck = function(index, message, code) {

        // Do not send requests if not connected
        if (!isConnected())
            return;

        tunnel.sendMessage("ack", index, message, code);
    };

    /**
     * Given the index of a file, writes a blob of data to that file.
     * 
     * @param {Number} index The index of the file to write to.
     * @param {String} data Base64-encoded data to write to the file.
     */
    this.sendBlob = function(index, data) {

        // Do not send requests if not connected
        if (!isConnected())
            return;

        tunnel.sendMessage("blob", index, data);
    };

    /**
     * Marks a currently-open stream as complete.
     * 
     * @param {Number} index The index of the stream to end.
     */
    this.endStream = function(index) {

        // Do not send requests if not connected
        if (!isConnected())
            return;

        tunnel.sendMessage("end", index);
    };

    /**
     * Fired whenever the state of this Guacamole.Client changes.
     * 
     * @event
     * @param {Number} state The new state of the client.
     */
    this.onstatechange = null;

    /**
     * Fired when the remote client sends a name update.
     * 
     * @event
     * @param {String} name The new name of this client.
     */
    this.onname = null;

    /**
     * Fired when an error is reported by the remote client, and the connection
     * is being closed.
     * 
     * @event
     * @param {Guacamole.Status} status A status object which describes the
     *                                  error.
     */
    this.onerror = null;

    /**
     * Fired when a audio stream is created. The stream provided to this event
     * handler will contain its own event handlers for received data.
     *
     * @event
     * @param {Guacamole.InputStream} stream
     *     The stream that will receive audio data from the server.
     *
     * @param {String} mimetype
     *     The mimetype of the audio data which will be received.
     *
     * @return {Guacamole.AudioPlayer}
     *     An object which implements the Guacamole.AudioPlayer interface and
     *     has been initialied to play the data in the provided stream, or null
     *     if the built-in audio players of the Guacamole client should be
     *     used.
     */
    this.onaudio = null;

    /**
     * Fired when a video stream is created. The stream provided to this event
     * handler will contain its own event handlers for received data.
     *
     * @event
     * @param {Guacamole.InputStream} stream
     *     The stream that will receive video data from the server.
     *
     * @param {Guacamole.Display.VisibleLayer} layer
     *     The destination layer on which the received video data should be
     *     played. It is the responsibility of the Guacamole.VideoPlayer
     *     implementation to play the received data within this layer.
     *
     * @param {String} mimetype
     *     The mimetype of the video data which will be received.
     *
     * @return {Guacamole.VideoPlayer}
     *     An object which implements the Guacamole.VideoPlayer interface and
     *     has been initialied to play the data in the provided stream, or null
     *     if the built-in video players of the Guacamole client should be
     *     used.
     */
    this.onvideo = null;

    /**
     * Fired when the clipboard of the remote client is changing.
     * 
     * @event
     * @param {Guacamole.InputStream} stream The stream that will receive
     *                                       clipboard data from the server.
     * @param {String} mimetype The mimetype of the data which will be received.
     */
    this.onclipboard = null;

    /**
     * Fired when a file stream is created. The stream provided to this event
     * handler will contain its own event handlers for received data.
     * 
     * @event
     * @param {Guacamole.InputStream} stream The stream that will receive data
     *                                       from the server.
     * @param {String} mimetype The mimetype of the file received.
     * @param {String} filename The name of the file received.
     */
    this.onfile = null;

    /**
     * Fired when a filesystem object is created. The object provided to this
     * event handler will contain its own event handlers and functions for
     * requesting and handling data.
     *
     * @event
     * @param {Guacamole.Object} object
     *     The created filesystem object.
     *
     * @param {String} name
     *     The name of the filesystem.
     */
    this.onfilesystem = null;

    /**
     * Fired when a pipe stream is created. The stream provided to this event
     * handler will contain its own event handlers for received data;
     * 
     * @event
     * @param {Guacamole.InputStream} stream The stream that will receive data
     *                                       from the server.
     * @param {String} mimetype The mimetype of the data which will be received.
     * @param {String} name The name of the pipe.
     */
    this.onpipe = null;

    /**
     * Fired whenever a sync instruction is received from the server, indicating
     * that the server is finished processing any input from the client and
     * has sent any results.
     * 
     * @event
     * @param {Number} timestamp The timestamp associated with the sync
     *                           instruction.
     */
    this.onsync = null;

    /**
     * Returns the layer with the given index, creating it if necessary.
     * Positive indices refer to visible layers, an index of zero refers to
     * the default layer, and negative indices refer to buffers.
     *
     * @private
     * @param {Number} index
     *     The index of the layer to retrieve.
     *
     * @return {Guacamole.Display.VisibleLayer|Guacamole.Layer}
     *     The layer having the given index.
     */
    var getLayer = function getLayer(index) {

        // Get layer, create if necessary
        var layer = layers[index];
        if (!layer) {

            // Create layer based on index
            if (index === 0)
                layer = display.getDefaultLayer();
            else if (index > 0)
                layer = display.createLayer();
            else
                layer = display.createBuffer();
                
            // Add new layer
            layers[index] = layer;

        }

        return layer;

    };

    function getParser(index) {

        var parser = parsers[index];

        // If parser not yet created, create it, and tie to the
        // oninstruction handler of the tunnel.
        if (parser == null) {
            parser = parsers[index] = new Guacamole.Parser();
            parser.oninstruction = tunnel.oninstruction;
        }

        return parser;

    }

    /**
     * Handlers for all defined layer properties.
     * @private
     */
    var layerPropertyHandlers = {

        "miter-limit": function(layer, value) {
            display.setMiterLimit(layer, parseFloat(value));
        }

    };
    
    /**
     * Handlers for all instruction opcodes receivable by a Guacamole protocol
     * client.
     * @private
     */
    var instructionHandlers = {

        "ack": function(parameters) {

            var stream_index = parseInt(parameters[0]);
            var reason = parameters[1];
            var code = parseInt(parameters[2]);

            // Get stream
            var stream = output_streams[stream_index];
            if (stream) {

                // Signal ack if handler defined
                if (stream.onack)
                    stream.onack(new Guacamole.Status(code, reason));

                // If code is an error, invalidate stream
                if (code >= 0x0100) {
                    stream_indices.free(stream_index);
                    delete output_streams[stream_index];
                }

            }

        },

        "arc": function(parameters) {

            var layer = getLayer(parseInt(parameters[0]));
            var x = parseInt(parameters[1]);
            var y = parseInt(parameters[2]);
            var radius = parseInt(parameters[3]);
            var startAngle = parseFloat(parameters[4]);
            var endAngle = parseFloat(parameters[5]);
            var negative = parseInt(parameters[6]);

            display.arc(layer, x, y, radius, startAngle, endAngle, negative != 0);

        },

        "audio": function(parameters) {

            var stream_index = parseInt(parameters[0]);
            var mimetype = parameters[1];

            // Create stream 
            var stream = streams[stream_index] =
                    new Guacamole.InputStream(guac_client, stream_index);

            // Get player instance via callback
            var audioPlayer = null;
            if (guac_client.onaudio)
                audioPlayer = guac_client.onaudio(stream, mimetype);

            // If unsuccessful, try to use a default implementation
            if (!audioPlayer)
                audioPlayer = Guacamole.AudioPlayer.getInstance(stream, mimetype);

            // If we have successfully retrieved an audio player, send success response
            if (audioPlayer) {
                audioPlayers[stream_index] = audioPlayer;
                guac_client.sendAck(stream_index, "OK", 0x0000);
            }

            // Otherwise, mimetype must be unsupported
            else
                guac_client.sendAck(stream_index, "BAD TYPE", 0x030F);

        },

        "blob": function(parameters) {

            // Get stream 
            var stream_index = parseInt(parameters[0]);
            var data = parameters[1];
            var stream = streams[stream_index];

            // Write data
            if (stream && stream.onblob)
                stream.onblob(data);

        },

        "body" : function handleBody(parameters) {

            // Get object
            var objectIndex = parseInt(parameters[0]);
            var object = objects[objectIndex];

            var streamIndex = parseInt(parameters[1]);
            var mimetype = parameters[2];
            var name = parameters[3];

            // Create stream if handler defined
            if (object && object.onbody) {
                var stream = streams[streamIndex] = new Guacamole.InputStream(guac_client, streamIndex);
                object.onbody(stream, mimetype, name);
            }

            // Otherwise, unsupported
            else
                guac_client.sendAck(streamIndex, "Receipt of body unsupported", 0x0100);

        },

        "cfill": function(parameters) {

            var channelMask = parseInt(parameters[0]);
            var layer = getLayer(parseInt(parameters[1]));
            var r = parseInt(parameters[2]);
            var g = parseInt(parameters[3]);
            var b = parseInt(parameters[4]);
            var a = parseInt(parameters[5]);

            display.setChannelMask(layer, channelMask);
            display.fillColor(layer, r, g, b, a);

        },

        "clip": function(parameters) {

            var layer = getLayer(parseInt(parameters[0]));

            display.clip(layer);

        },

        "clipboard": function(parameters) {

            var stream_index = parseInt(parameters[0]);
            var mimetype = parameters[1];

            // Create stream 
            if (guac_client.onclipboard) {
                var stream = streams[stream_index] = new Guacamole.InputStream(guac_client, stream_index);
                guac_client.onclipboard(stream, mimetype);
            }

            // Otherwise, unsupported
            else
                guac_client.sendAck(stream_index, "Clipboard unsupported", 0x0100);

        },

        "close": function(parameters) {

            var layer = getLayer(parseInt(parameters[0]));

            display.close(layer);

        },

        "copy": function(parameters) {

            var srcL = getLayer(parseInt(parameters[0]));
            var srcX = parseInt(parameters[1]);
            var srcY = parseInt(parameters[2]);
            var srcWidth = parseInt(parameters[3]);
            var srcHeight = parseInt(parameters[4]);
            var channelMask = parseInt(parameters[5]);
            var dstL = getLayer(parseInt(parameters[6]));
            var dstX = parseInt(parameters[7]);
            var dstY = parseInt(parameters[8]);

            display.setChannelMask(dstL, channelMask);
            display.copy(srcL, srcX, srcY, srcWidth, srcHeight, 
                         dstL, dstX, dstY);

        },

        "cstroke": function(parameters) {

            var channelMask = parseInt(parameters[0]);
            var layer = getLayer(parseInt(parameters[1]));
            var cap = lineCap[parseInt(parameters[2])];
            var join = lineJoin[parseInt(parameters[3])];
            var thickness = parseInt(parameters[4]);
            var r = parseInt(parameters[5]);
            var g = parseInt(parameters[6]);
            var b = parseInt(parameters[7]);
            var a = parseInt(parameters[8]);

            display.setChannelMask(layer, channelMask);
            display.strokeColor(layer, cap, join, thickness, r, g, b, a);

        },

        "cursor": function(parameters) {

            var cursorHotspotX = parseInt(parameters[0]);
            var cursorHotspotY = parseInt(parameters[1]);
            var srcL = getLayer(parseInt(parameters[2]));
            var srcX = parseInt(parameters[3]);
            var srcY = parseInt(parameters[4]);
            var srcWidth = parseInt(parameters[5]);
            var srcHeight = parseInt(parameters[6]);

            display.setCursor(cursorHotspotX, cursorHotspotY,
                              srcL, srcX, srcY, srcWidth, srcHeight);

        },

        "curve": function(parameters) {

            var layer = getLayer(parseInt(parameters[0]));
            var cp1x = parseInt(parameters[1]);
            var cp1y = parseInt(parameters[2]);
            var cp2x = parseInt(parameters[3]);
            var cp2y = parseInt(parameters[4]);
            var x = parseInt(parameters[5]);
            var y = parseInt(parameters[6]);

            display.curveTo(layer, cp1x, cp1y, cp2x, cp2y, x, y);

        },

        "dispose": function(parameters) {
            
            var layer_index = parseInt(parameters[0]);

            // If visible layer, remove from parent
            if (layer_index > 0) {

                // Remove from parent
                var layer = getLayer(layer_index);
                layer.dispose();

                // Delete reference
                delete layers[layer_index];

            }

            // If buffer, just delete reference
            else if (layer_index < 0)
                delete layers[layer_index];

            // Attempting to dispose the root layer currently has no effect.

        },

        "distort": function(parameters) {

            var layer_index = parseInt(parameters[0]);
            var a = parseFloat(parameters[1]);
            var b = parseFloat(parameters[2]);
            var c = parseFloat(parameters[3]);
            var d = parseFloat(parameters[4]);
            var e = parseFloat(parameters[5]);
            var f = parseFloat(parameters[6]);

            // Only valid for visible layers (not buffers)
            if (layer_index >= 0) {
                var layer = getLayer(layer_index);
                layer.distort(a, b, c, d, e, f);
            }

        },
 
        "error": function(parameters) {

            var reason = parameters[0];
            var code = parseInt(parameters[1]);

            // Call handler if defined
            if (guac_client.onerror)
                guac_client.onerror(new Guacamole.Status(code, reason));

            guac_client.disconnect();

        },

        "end": function(parameters) {

            // Get stream
            var stream_index = parseInt(parameters[0]);
            var stream = streams[stream_index];

            // Signal end of stream
            if (stream && stream.onend)
                stream.onend();

        },

        "file": function(parameters) {

            var stream_index = parseInt(parameters[0]);
            var mimetype = parameters[1];
            var filename = parameters[2];

            // Create stream 
            if (guac_client.onfile) {
                var stream = streams[stream_index] = new Guacamole.InputStream(guac_client, stream_index);
                guac_client.onfile(stream, mimetype, filename);
            }

            // Otherwise, unsupported
            else
                guac_client.sendAck(stream_index, "File transfer unsupported", 0x0100);

        },

        "filesystem" : function handleFilesystem(parameters) {

            var objectIndex = parseInt(parameters[0]);
            var name = parameters[1];

            // Create object, if supported
            if (guac_client.onfilesystem) {
                var object = objects[objectIndex] = new Guacamole.Object(guac_client, objectIndex);
                guac_client.onfilesystem(object, name);
            }

            // If unsupported, simply ignore the availability of the filesystem

        },

        "identity": function(parameters) {

            var layer = getLayer(parseInt(parameters[0]));

            display.setTransform(layer, 1, 0, 0, 1, 0, 0);

        },

        "img": function(parameters) {

            var stream_index = parseInt(parameters[0]);
            var channelMask = parseInt(parameters[1]);
            var layer = getLayer(parseInt(parameters[2]));
            var mimetype = parameters[3];
            var x = parseInt(parameters[4]);
            var y = parseInt(parameters[5]);

            // Create stream
            var stream = streams[stream_index] = new Guacamole.InputStream(guac_client, stream_index);
            var reader = new Guacamole.DataURIReader(stream, mimetype);

            // Draw image when stream is complete
            reader.onend = function drawImageBlob() {
                display.setChannelMask(layer, channelMask);
                display.draw(layer, x, y, reader.getURI());
            };

        },

        "jpeg": function(parameters) {

            var channelMask = parseInt(parameters[0]);
            var layer = getLayer(parseInt(parameters[1]));
            var x = parseInt(parameters[2]);
            var y = parseInt(parameters[3]);
            var data = parameters[4];

            display.setChannelMask(layer, channelMask);
            display.draw(layer, x, y, "data:image/jpeg;base64," + data);

        },

        "lfill": function(parameters) {

            var channelMask = parseInt(parameters[0]);
            var layer = getLayer(parseInt(parameters[1]));
            var srcLayer = getLayer(parseInt(parameters[2]));

            display.setChannelMask(layer, channelMask);
            display.fillLayer(layer, srcLayer);

        },

        "line": function(parameters) {

            var layer = getLayer(parseInt(parameters[0]));
            var x = parseInt(parameters[1]);
            var y = parseInt(parameters[2]);

            display.lineTo(layer, x, y);

        },

        "lstroke": function(parameters) {

            var channelMask = parseInt(parameters[0]);
            var layer = getLayer(parseInt(parameters[1]));
            var srcLayer = getLayer(parseInt(parameters[2]));

            display.setChannelMask(layer, channelMask);
            display.strokeLayer(layer, srcLayer);

        },

        "move": function(parameters) {
            
            var layer_index = parseInt(parameters[0]);
            var parent_index = parseInt(parameters[1]);
            var x = parseInt(parameters[2]);
            var y = parseInt(parameters[3]);
            var z = parseInt(parameters[4]);

            // Only valid for non-default layers
            if (layer_index > 0 && parent_index >= 0) {
                var layer = getLayer(layer_index);
                var parent = getLayer(parent_index);
                layer.move(parent, x, y, z);
            }

        },

        "name": function(parameters) {
            if (guac_client.onname) guac_client.onname(parameters[0]);
        },

        "nest": function(parameters) {
            var parser = getParser(parseInt(parameters[0]));
            parser.receive(parameters[1]);
        },

        "pipe": function(parameters) {

            var stream_index = parseInt(parameters[0]);
            var mimetype = parameters[1];
            var name = parameters[2];

            // Create stream 
            if (guac_client.onpipe) {
                var stream = streams[stream_index] = new Guacamole.InputStream(guac_client, stream_index);
                guac_client.onpipe(stream, mimetype, name);
            }

            // Otherwise, unsupported
            else
                guac_client.sendAck(stream_index, "Named pipes unsupported", 0x0100);

        },

        "png": function(parameters) {

            var channelMask = parseInt(parameters[0]);
            var layer = getLayer(parseInt(parameters[1]));
            var x = parseInt(parameters[2]);
            var y = parseInt(parameters[3]);
            var data = parameters[4];

            display.setChannelMask(layer, channelMask);
            display.draw(layer, x, y, "data:image/png;base64," + data);

        },

        "pop": function(parameters) {

            var layer = getLayer(parseInt(parameters[0]));

            display.pop(layer);

        },

        "push": function(parameters) {

            var layer = getLayer(parseInt(parameters[0]));

            display.push(layer);

        },
 
        "rect": function(parameters) {

            var layer = getLayer(parseInt(parameters[0]));
            var x = parseInt(parameters[1]);
            var y = parseInt(parameters[2]);
            var w = parseInt(parameters[3]);
            var h = parseInt(parameters[4]);

            display.rect(layer, x, y, w, h);

        },
        
        "reset": function(parameters) {

            var layer = getLayer(parseInt(parameters[0]));

            display.reset(layer);

        },
        
        "set": function(parameters) {

            var layer = getLayer(parseInt(parameters[0]));
            var name = parameters[1];
            var value = parameters[2];

            // Call property handler if defined
            var handler = layerPropertyHandlers[name];
            if (handler)
                handler(layer, value);

        },

        "shade": function(parameters) {
            
            var layer_index = parseInt(parameters[0]);
            var a = parseInt(parameters[1]);

            // Only valid for visible layers (not buffers)
            if (layer_index >= 0) {
                var layer = getLayer(layer_index);
                layer.shade(a);
            }

        },

        "size": function(parameters) {

            var layer_index = parseInt(parameters[0]);
            var layer = getLayer(layer_index);
            var width = parseInt(parameters[1]);
            var height = parseInt(parameters[2]);

            display.resize(layer, width, height);

        },
        
        "start": function(parameters) {

            var layer = getLayer(parseInt(parameters[0]));
            var x = parseInt(parameters[1]);
            var y = parseInt(parameters[2]);

            display.moveTo(layer, x, y);

        },

        "sync": function(parameters) {

            var timestamp = parseInt(parameters[0]);

            // Flush display, send sync when done
            display.flush(function displaySyncComplete() {

                // Synchronize all audio players
                for (var index in audioPlayers) {
                    var audioPlayer = audioPlayers[index];
                    if (audioPlayer)
                        audioPlayer.sync();
                }

                // Send sync response to server
                if (timestamp !== currentTimestamp) {
                    tunnel.sendMessage("sync", timestamp);
                    currentTimestamp = timestamp;
                }

            });

            // If received first update, no longer waiting.
            if (currentState === STATE_WAITING)
                setState(STATE_CONNECTED);

            // Call sync handler if defined
            if (guac_client.onsync)
                guac_client.onsync(timestamp);

        },

        "transfer": function(parameters) {

            var srcL = getLayer(parseInt(parameters[0]));
            var srcX = parseInt(parameters[1]);
            var srcY = parseInt(parameters[2]);
            var srcWidth = parseInt(parameters[3]);
            var srcHeight = parseInt(parameters[4]);
            var function_index = parseInt(parameters[5]);
            var dstL = getLayer(parseInt(parameters[6]));
            var dstX = parseInt(parameters[7]);
            var dstY = parseInt(parameters[8]);

            /* SRC */
            if (function_index === 0x3)
                display.put(srcL, srcX, srcY, srcWidth, srcHeight, 
                    dstL, dstX, dstY);

            /* Anything else that isn't a NO-OP */
            else if (function_index !== 0x5)
                display.transfer(srcL, srcX, srcY, srcWidth, srcHeight, 
                    dstL, dstX, dstY, Guacamole.Client.DefaultTransferFunction[function_index]);

        },

        "transform": function(parameters) {

            var layer = getLayer(parseInt(parameters[0]));
            var a = parseFloat(parameters[1]);
            var b = parseFloat(parameters[2]);
            var c = parseFloat(parameters[3]);
            var d = parseFloat(parameters[4]);
            var e = parseFloat(parameters[5]);
            var f = parseFloat(parameters[6]);

            display.transform(layer, a, b, c, d, e, f);

        },

        "undefine" : function handleUndefine(parameters) {

            // Get object
            var objectIndex = parseInt(parameters[0]);
            var object = objects[objectIndex];

            // Signal end of object definition
            if (object && object.onundefine)
                object.onundefine();

        },

        "video": function(parameters) {

            var stream_index = parseInt(parameters[0]);
            var layer = getLayer(parseInt(parameters[1]));
            var mimetype = parameters[2];

            // Create stream
            var stream = streams[stream_index] =
                    new Guacamole.InputStream(guac_client, stream_index);

            // Get player instance via callback
            var videoPlayer = null;
            if (guac_client.onvideo)
                videoPlayer = guac_client.onvideo(stream, layer, mimetype);

            // If unsuccessful, try to use a default implementation
            if (!videoPlayer)
                videoPlayer = Guacamole.VideoPlayer.getInstance(stream, layer, mimetype);

            // If we have successfully retrieved an video player, send success response
            if (videoPlayer) {
                videoPlayers[stream_index] = videoPlayer;
                guac_client.sendAck(stream_index, "OK", 0x0000);
            }

            // Otherwise, mimetype must be unsupported
            else
                guac_client.sendAck(stream_index, "BAD TYPE", 0x030F);

        }

    };

    tunnel.oninstruction = function(opcode, parameters) {

        var handler = instructionHandlers[opcode];
        if (handler)
            handler(parameters);

    };

    /**
     * Sends a disconnect instruction to the server and closes the tunnel.
     */
    this.disconnect = function() {

        // Only attempt disconnection not disconnected.
        if (currentState != STATE_DISCONNECTED
                && currentState != STATE_DISCONNECTING) {

            setState(STATE_DISCONNECTING);

            // Stop ping
            if (pingInterval)
                window.clearInterval(pingInterval);

            // Send disconnect message and disconnect
            tunnel.sendMessage("disconnect");
            tunnel.disconnect();
            setState(STATE_DISCONNECTED);

        }

    };
    
    /**
     * Connects the underlying tunnel of this Guacamole.Client, passing the
     * given arbitrary data to the tunnel during the connection process.
     *
     * @param data Arbitrary connection data to be sent to the underlying
     *             tunnel during the connection process.
     * @throws {Guacamole.Status} If an error occurs during connection.
     */
    this.connect = function(data) {

        setState(STATE_CONNECTING);

        try {
            tunnel.connect(data);
        }
        catch (status) {
            setState(STATE_IDLE);
            throw status;
        }

        // Ping every 5 seconds (ensure connection alive)
        pingInterval = window.setInterval(function() {
            tunnel.sendMessage("sync", currentTimestamp);
        }, 5000);

        setState(STATE_WAITING);
    };

};

/**
 * Map of all Guacamole binary raster operations to transfer functions.
 * @private
 */
Guacamole.Client.DefaultTransferFunction = {

    /* BLACK */
    0x0: function (src, dst) {
        dst.red = dst.green = dst.blue = 0x00;
    },

    /* WHITE */
    0xF: function (src, dst) {
        dst.red = dst.green = dst.blue = 0xFF;
    },

    /* SRC */
    0x3: function (src, dst) {
        dst.red   = src.red;
        dst.green = src.green;
        dst.blue  = src.blue;
        dst.alpha = src.alpha;
    },

    /* DEST (no-op) */
    0x5: function (src, dst) {
        // Do nothing
    },

    /* Invert SRC */
    0xC: function (src, dst) {
        dst.red   = 0xFF & ~src.red;
        dst.green = 0xFF & ~src.green;
        dst.blue  = 0xFF & ~src.blue;
        dst.alpha =  src.alpha;
    },
    
    /* Invert DEST */
    0xA: function (src, dst) {
        dst.red   = 0xFF & ~dst.red;
        dst.green = 0xFF & ~dst.green;
        dst.blue  = 0xFF & ~dst.blue;
    },

    /* AND */
    0x1: function (src, dst) {
        dst.red   =  ( src.red   &  dst.red);
        dst.green =  ( src.green &  dst.green);
        dst.blue  =  ( src.blue  &  dst.blue);
    },

    /* NAND */
    0xE: function (src, dst) {
        dst.red   = 0xFF & ~( src.red   &  dst.red);
        dst.green = 0xFF & ~( src.green &  dst.green);
        dst.blue  = 0xFF & ~( src.blue  &  dst.blue);
    },

    /* OR */
    0x7: function (src, dst) {
        dst.red   =  ( src.red   |  dst.red);
        dst.green =  ( src.green |  dst.green);
        dst.blue  =  ( src.blue  |  dst.blue);
    },

    /* NOR */
    0x8: function (src, dst) {
        dst.red   = 0xFF & ~( src.red   |  dst.red);
        dst.green = 0xFF & ~( src.green |  dst.green);
        dst.blue  = 0xFF & ~( src.blue  |  dst.blue);
    },

    /* XOR */
    0x6: function (src, dst) {
        dst.red   =  ( src.red   ^  dst.red);
        dst.green =  ( src.green ^  dst.green);
        dst.blue  =  ( src.blue  ^  dst.blue);
    },

    /* XNOR */
    0x9: function (src, dst) {
        dst.red   = 0xFF & ~( src.red   ^  dst.red);
        dst.green = 0xFF & ~( src.green ^  dst.green);
        dst.blue  = 0xFF & ~( src.blue  ^  dst.blue);
    },

    /* AND inverted source */
    0x4: function (src, dst) {
        dst.red   =  0xFF & (~src.red   &  dst.red);
        dst.green =  0xFF & (~src.green &  dst.green);
        dst.blue  =  0xFF & (~src.blue  &  dst.blue);
    },

    /* OR inverted source */
    0xD: function (src, dst) {
        dst.red   =  0xFF & (~src.red   |  dst.red);
        dst.green =  0xFF & (~src.green |  dst.green);
        dst.blue  =  0xFF & (~src.blue  |  dst.blue);
    },

    /* AND inverted destination */
    0x2: function (src, dst) {
        dst.red   =  0xFF & ( src.red   & ~dst.red);
        dst.green =  0xFF & ( src.green & ~dst.green);
        dst.blue  =  0xFF & ( src.blue  & ~dst.blue);
    },

    /* OR inverted destination */
    0xB: function (src, dst) {
        dst.red   =  0xFF & ( src.red   | ~dst.red);
        dst.green =  0xFF & ( src.green | ~dst.green);
        dst.blue  =  0xFF & ( src.blue  | ~dst.blue);
    }

};
