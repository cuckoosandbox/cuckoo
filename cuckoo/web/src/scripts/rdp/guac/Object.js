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
 * An object used by the Guacamole client to house arbitrarily-many named
 * input and output streams.
 * 
 * @constructor
 * @param {Guacamole.Client} client
 *     The client owning this object.
 *
 * @param {Number} index
 *     The index of this object.
 */
Guacamole.Object = function guacamoleObject(client, index) {

    /**
     * Reference to this Guacamole.Object.
     *
     * @private
     * @type {Guacamole.Object}
     */
    var guacObject = this;

    /**
     * Map of stream name to corresponding queue of callbacks. The queue of
     * callbacks is guaranteed to be in order of request.
     *
     * @private
     * @type {Object.<String, Function[]>}
     */
    var bodyCallbacks = {};

    /**
     * Removes and returns the callback at the head of the callback queue for
     * the stream having the given name. If no such callbacks exist, null is
     * returned.
     *
     * @private
     * @param {String} name
     *     The name of the stream to retrieve a callback for.
     *
     * @returns {Function}
     *     The next callback associated with the stream having the given name,
     *     or null if no such callback exists.
     */
    var dequeueBodyCallback = function dequeueBodyCallback(name) {

        // If no callbacks defined, simply return null
        var callbacks = bodyCallbacks[name];
        if (!callbacks)
            return null;

        // Otherwise, pull off first callback, deleting the queue if empty
        var callback = callbacks.shift();
        if (callbacks.length === 0)
            delete bodyCallbacks[name];

        // Return found callback
        return callback;

    };

    /**
     * Adds the given callback to the tail of the callback queue for the stream
     * having the given name.
     *
     * @private
     * @param {String} name
     *     The name of the stream to associate with the given callback.
     *
     * @param {Function} callback
     *     The callback to add to the queue of the stream with the given name.
     */
    var enqueueBodyCallback = function enqueueBodyCallback(name, callback) {

        // Get callback queue by name, creating first if necessary
        var callbacks = bodyCallbacks[name];
        if (!callbacks) {
            callbacks = [];
            bodyCallbacks[name] = callbacks;
        }

        // Add callback to end of queue
        callbacks.push(callback);

    };

    /**
     * The index of this object.
     *
     * @type {Number}
     */
    this.index = index;

    /**
     * Called when this object receives the body of a requested input stream.
     * By default, all objects will invoke the callbacks provided to their
     * requestInputStream() functions based on the name of the stream
     * requested. This behavior can be overridden by specifying a different
     * handler here.
     *
     * @event
     * @param {Guacamole.InputStream} inputStream
     *     The input stream of the received body.
     *
     * @param {String} mimetype
     *     The mimetype of the data being received.
     *
     * @param {String} name
     *     The name of the stream whose body has been received.
     */
    this.onbody = function defaultBodyHandler(inputStream, mimetype, name) {

        // Call queued callback for the received body, if any
        var callback = dequeueBodyCallback(name);
        if (callback)
            callback(inputStream, mimetype);

    };

    /**
     * Called when this object is being undefined. Once undefined, no further
     * communication involving this object may occur.
     * 
     * @event
     */
    this.onundefine = null;

    /**
     * Requests read access to the input stream having the given name. If
     * successful, a new input stream will be created.
     *
     * @param {String} name
     *     The name of the input stream to request.
     *
     * @param {Function} [bodyCallback]
     *     The callback to invoke when the body of the requested input stream
     *     is received. This callback will be provided a Guacamole.InputStream
     *     and its mimetype as its two only arguments. If the onbody handler of
     *     this object is overridden, this callback will not be invoked.
     */
    this.requestInputStream = function requestInputStream(name, bodyCallback) {

        // Queue body callback if provided
        if (bodyCallback)
            enqueueBodyCallback(name, bodyCallback);

        // Send request for input stream
        client.requestObjectInputStream(guacObject.index, name);

    };

    /**
     * Creates a new output stream associated with this object and having the
     * given mimetype and name. The legality of a mimetype and name is dictated
     * by the object itself.
     *
     * @param {String} mimetype
     *     The mimetype of the data which will be sent to the output stream.
     *
     * @param {String} name
     *     The defined name of an output stream within this object.
     *
     * @returns {Guacamole.OutputStream}
     *     An output stream which will write blobs to the named output stream
     *     of this object.
     */
    this.createOutputStream = function createOutputStream(mimetype, name) {
        return client.createObjectOutputStream(guacObject.index, mimetype, name);
    };

};

/**
 * The reserved name denoting the root stream of any object. The contents of
 * the root stream MUST be a JSON map of stream name to mimetype.
 *
 * @constant
 * @type {String}
 */
Guacamole.Object.ROOT_STREAM = '/';

/**
 * The mimetype of a stream containing JSON which maps available stream names
 * to their corresponding mimetype. The root stream of a Guacamole.Object MUST
 * have this mimetype.
 *
 * @constant
 * @type {String}
 */
Guacamole.Object.STREAM_INDEX_MIMETYPE = 'application/vnd.glyptodon.guacamole.stream-index+json';
