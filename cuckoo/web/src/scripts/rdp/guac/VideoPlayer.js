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
 * Abstract video player which accepts, queues and plays back arbitrary video
 * data. It is up to implementations of this class to provide some means of
 * handling a provided Guacamole.InputStream and rendering the received data to
 * the provided Guacamole.Display.VisibleLayer. Data received along the
 * provided stream is to be played back immediately.
 *
 * @constructor
 */
Guacamole.VideoPlayer = function VideoPlayer() {

    /**
     * Notifies this Guacamole.VideoPlayer that all video up to the current
     * point in time has been given via the underlying stream, and that any
     * difference in time between queued video data and the current time can be
     * considered latency.
     */
    this.sync = function sync() {
        // Default implementation - do nothing
    };

};

/**
 * Determines whether the given mimetype is supported by any built-in
 * implementation of Guacamole.VideoPlayer, and thus will be properly handled
 * by Guacamole.VideoPlayer.getInstance().
 *
 * @param {String} mimetype
 *     The mimetype to check.
 *
 * @returns {Boolean}
 *     true if the given mimetype is supported by any built-in
 *     Guacamole.VideoPlayer, false otherwise.
 */
Guacamole.VideoPlayer.isSupportedType = function isSupportedType(mimetype) {

    // There are currently no built-in video players (and therefore no
    // supported types)
    return false;

};

/**
 * Returns a list of all mimetypes supported by any built-in
 * Guacamole.VideoPlayer, in rough order of priority. Beware that only the core
 * mimetypes themselves will be listed. Any mimetype parameters, even required
 * ones, will not be included in the list.
 *
 * @returns {String[]}
 *     A list of all mimetypes supported by any built-in Guacamole.VideoPlayer,
 *     excluding any parameters.
 */
Guacamole.VideoPlayer.getSupportedTypes = function getSupportedTypes() {

    // There are currently no built-in video players (and therefore no
    // supported types)
    return [];

};

/**
 * Returns an instance of Guacamole.VideoPlayer providing support for the given
 * video format. If support for the given video format is not available, null
 * is returned.
 *
 * @param {Guacamole.InputStream} stream
 *     The Guacamole.InputStream to read video data from.
 *
 * @param {Guacamole.Display.VisibleLayer} layer
 *     The destination layer in which this Guacamole.VideoPlayer should play
 *     the received video data.
 *
 * @param {String} mimetype
 *     The mimetype of the video data in the provided stream.
 *
 * @return {Guacamole.VideoPlayer}
 *     A Guacamole.VideoPlayer instance supporting the given mimetype and
 *     reading from the given stream, or null if support for the given mimetype
 *     is absent.
 */
Guacamole.VideoPlayer.getInstance = function getInstance(stream, layer, mimetype) {

    // There are currently no built-in video players
    return null;

};
