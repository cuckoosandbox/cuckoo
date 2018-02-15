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
 * A description of the format of raw PCM audio, such as that used by
 * Guacamole.RawAudioPlayer and Guacamole.RawAudioRecorder. This object
 * describes the number of bytes per sample, the number of channels, and the
 * overall sample rate.
 *
 * @constructor
 * @param {Guacamole.RawAudioFormat|Object} template
 *     The object whose properties should be copied into the corresponding
 *     properties of the new Guacamole.RawAudioFormat.
 */
Guacamole.RawAudioFormat = function RawAudioFormat(template) {

    /**
     * The number of bytes in each sample of audio data. This value is
     * independent of the number of channels.
     *
     * @type {Number}
     */
    this.bytesPerSample = template.bytesPerSample;

    /**
     * The number of audio channels (ie: 1 for mono, 2 for stereo).
     *
     * @type {Number}
     */
    this.channels = template.channels;

    /**
     * The number of samples per second, per channel.
     *
     * @type {Number}
     */
    this.rate = template.rate;

};

/**
 * Parses the given mimetype, returning a new Guacamole.RawAudioFormat
 * which describes the type of raw audio data represented by that mimetype. If
 * the mimetype is not a supported raw audio data mimetype, null is returned.
 *
 * @param {String} mimetype
 *     The audio mimetype to parse.
 *
 * @returns {Guacamole.RawAudioFormat}
 *     A new Guacamole.RawAudioFormat which describes the type of raw
 *     audio data represented by the given mimetype, or null if the given
 *     mimetype is not supported.
 */
Guacamole.RawAudioFormat.parse = function parseFormat(mimetype) {

    var bytesPerSample;

    // Rate is absolutely required - if null is still present later, the
    // mimetype must not be supported
    var rate = null;

    // Default for both "audio/L8" and "audio/L16" is one channel
    var channels = 1;

    // "audio/L8" has one byte per sample
    if (mimetype.substring(0, 9) === 'audio/L8;') {
        mimetype = mimetype.substring(9);
        bytesPerSample = 1;
    }

    // "audio/L16" has two bytes per sample
    else if (mimetype.substring(0, 10) === 'audio/L16;') {
        mimetype = mimetype.substring(10);
        bytesPerSample = 2;
    }

    // All other types are unsupported
    else
        return null;

    // Parse all parameters
    var parameters = mimetype.split(',');
    for (var i = 0; i < parameters.length; i++) {

        var parameter = parameters[i];

        // All parameters must have an equals sign separating name from value
        var equals = parameter.indexOf('=');
        if (equals === -1)
            return null;

        // Parse name and value from parameter string
        var name  = parameter.substring(0, equals);
        var value = parameter.substring(equals+1);

        // Handle each supported parameter
        switch (name) {

            // Number of audio channels
            case 'channels':
                channels = parseInt(value);
                break;

            // Sample rate
            case 'rate':
                rate = parseInt(value);
                break;

            // All other parameters are unsupported
            default:
                return null;

        }

    };

    // The rate parameter is required
    if (rate === null)
        return null;

    // Return parsed format details
    return new Guacamole.RawAudioFormat({
        bytesPerSample : bytesPerSample,
        channels       : channels,
        rate           : rate
    });

};
