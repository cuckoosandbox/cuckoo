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
 * Abstract audio player which accepts, queues and plays back arbitrary audio
 * data. It is up to implementations of this class to provide some means of
 * handling a provided Guacamole.InputStream. Data received along the provided
 * stream is to be played back immediately.
 *
 * @constructor
 */
Guacamole.AudioPlayer = function AudioPlayer() {

    /**
     * Notifies this Guacamole.AudioPlayer that all audio up to the current
     * point in time has been given via the underlying stream, and that any
     * difference in time between queued audio data and the current time can be
     * considered latency.
     */
    this.sync = function sync() {
        // Default implementation - do nothing
    };

};

/**
 * Determines whether the given mimetype is supported by any built-in
 * implementation of Guacamole.AudioPlayer, and thus will be properly handled
 * by Guacamole.AudioPlayer.getInstance().
 *
 * @param {String} mimetype
 *     The mimetype to check.
 *
 * @returns {Boolean}
 *     true if the given mimetype is supported by any built-in
 *     Guacamole.AudioPlayer, false otherwise.
 */
Guacamole.AudioPlayer.isSupportedType = function isSupportedType(mimetype) {

    return Guacamole.RawAudioPlayer.isSupportedType(mimetype);

};

/**
 * Returns a list of all mimetypes supported by any built-in
 * Guacamole.AudioPlayer, in rough order of priority. Beware that only the core
 * mimetypes themselves will be listed. Any mimetype parameters, even required
 * ones, will not be included in the list. For example, "audio/L8" is a
 * supported raw audio mimetype that is supported, but it is invalid without
 * additional parameters. Something like "audio/L8;rate=44100" would be valid,
 * however (see https://tools.ietf.org/html/rfc4856).
 *
 * @returns {String[]}
 *     A list of all mimetypes supported by any built-in Guacamole.AudioPlayer,
 *     excluding any parameters.
 */
Guacamole.AudioPlayer.getSupportedTypes = function getSupportedTypes() {

    return Guacamole.RawAudioPlayer.getSupportedTypes();

};

/**
 * Returns an instance of Guacamole.AudioPlayer providing support for the given
 * audio format. If support for the given audio format is not available, null
 * is returned.
 *
 * @param {Guacamole.InputStream} stream
 *     The Guacamole.InputStream to read audio data from.
 *
 * @param {String} mimetype
 *     The mimetype of the audio data in the provided stream.
 *
 * @return {Guacamole.AudioPlayer}
 *     A Guacamole.AudioPlayer instance supporting the given mimetype and
 *     reading from the given stream, or null if support for the given mimetype
 *     is absent.
 */
Guacamole.AudioPlayer.getInstance = function getInstance(stream, mimetype) {

    // Use raw audio player if possible
    if (Guacamole.RawAudioPlayer.isSupportedType(mimetype))
        return new Guacamole.RawAudioPlayer(stream, mimetype);

    // No support for given mimetype
    return null;

};

/**
 * Implementation of Guacamole.AudioPlayer providing support for raw PCM format
 * audio. This player relies only on the Web Audio API and does not require any
 * browser-level support for its audio formats.
 *
 * @constructor
 * @augments Guacamole.AudioPlayer
 * @param {Guacamole.InputStream} stream
 *     The Guacamole.InputStream to read audio data from.
 *
 * @param {String} mimetype
 *     The mimetype of the audio data in the provided stream, which must be a
 *     "audio/L8" or "audio/L16" mimetype with necessary parameters, such as:
 *     "audio/L16;rate=44100,channels=2".
 */
Guacamole.RawAudioPlayer = function RawAudioPlayer(stream, mimetype) {

    /**
     * The format of audio this player will decode.
     *
     * @private
     * @type {Guacamole.RawAudioFormat}
     */
    var format = Guacamole.RawAudioFormat.parse(mimetype);

    /**
     * An instance of a Web Audio API AudioContext object, or null if the
     * Web Audio API is not supported.
     *
     * @private
     * @type {AudioContext}
     */
    var context = Guacamole.AudioContextFactory.getAudioContext();

    /**
     * The earliest possible time that the next packet could play without
     * overlapping an already-playing packet, in seconds. Note that while this
     * value is in seconds, it is not an integer value and has microsecond
     * resolution.
     *
     * @private
     * @type {Number}
     */
    var nextPacketTime = context.currentTime;

    /**
     * Guacamole.ArrayBufferReader wrapped around the audio input stream
     * provided with this Guacamole.RawAudioPlayer was created.
     *
     * @private
     * @type {Guacamole.ArrayBufferReader}
     */
    var reader = new Guacamole.ArrayBufferReader(stream);

    /**
     * The minimum size of an audio packet split by splitAudioPacket(), in
     * seconds. Audio packets smaller than this will not be split, nor will the
     * split result of a larger packet ever be smaller in size than this
     * minimum.
     *
     * @private
     * @constant
     * @type {Number}
     */
    var MIN_SPLIT_SIZE = 0.02;

    /**
     * The maximum amount of latency to allow between the buffered data stream
     * and the playback position, in seconds. Initially, this is set to
     * roughly one third of a second.
     *
     * @private
     * @type {Number}
     */
    var maxLatency = 0.3;

    /**
     * The type of typed array that will be used to represent each audio packet
     * internally. This will be either Int8Array or Int16Array, depending on
     * whether the raw audio format is 8-bit or 16-bit.
     *
     * @private
     * @constructor
     */
    var SampleArray = (format.bytesPerSample === 1) ? window.Int8Array : window.Int16Array;

    /**
     * The maximum absolute value of any sample within a raw audio packet
     * received by this audio player. This depends only on the size of each
     * sample, and will be 128 for 8-bit audio and 32768 for 16-bit audio.
     *
     * @private
     * @type {Number}
     */
    var maxSampleValue = (format.bytesPerSample === 1) ? 128 : 32768;

    /**
     * The queue of all pending audio packets, as an array of sample arrays.
     * Audio packets which are pending playback will be added to this queue for
     * further manipulation prior to scheduling via the Web Audio API. Once an
     * audio packet leaves this queue and is scheduled via the Web Audio API,
     * no further modifications can be made to that packet.
     *
     * @private
     * @type {SampleArray[]}
     */
    var packetQueue = [];

    /**
     * Given an array of audio packets, returns a single audio packet
     * containing the concatenation of those packets.
     *
     * @private
     * @param {SampleArray[]} packets
     *     The array of audio packets to concatenate.
     *
     * @returns {SampleArray}
     *     A single audio packet containing the concatenation of all given
     *     audio packets. If no packets are provided, this will be undefined.
     */
    var joinAudioPackets = function joinAudioPackets(packets) {

        // Do not bother joining if one or fewer packets are in the queue
        if (packets.length <= 1)
            return packets[0];

        // Determine total sample length of the entire queue
        var totalLength = 0;
        packets.forEach(function addPacketLengths(packet) {
            totalLength += packet.length;
        });

        // Append each packet within queue
        var offset = 0;
        var joined = new SampleArray(totalLength);
        packets.forEach(function appendPacket(packet) {
            joined.set(packet, offset);
            offset += packet.length;
        });

        return joined;

    };

    /**
     * Given a single packet of audio data, splits off an arbitrary length of
     * audio data from the beginning of that packet, returning the split result
     * as an array of two packets. The split location is determined through an
     * algorithm intended to minimize the liklihood of audible clicking between
     * packets. If no such split location is possible, an array containing only
     * the originally-provided audio packet is returned.
     *
     * @private
     * @param {SampleArray} data
     *     The audio packet to split.
     *
     * @returns {SampleArray[]}
     *     An array of audio packets containing the result of splitting the
     *     provided audio packet. If splitting is possible, this array will
     *     contain two packets. If splitting is not possible, this array will
     *     contain only the originally-provided packet.
     */
    var splitAudioPacket = function splitAudioPacket(data) {

        var minValue = Number.MAX_VALUE;
        var optimalSplitLength = data.length;

        // Calculate number of whole samples in the provided audio packet AND
        // in the minimum possible split packet
        var samples = Math.floor(data.length / format.channels);
        var minSplitSamples = Math.floor(format.rate * MIN_SPLIT_SIZE);

        // Calculate the beginning of the "end" of the audio packet
        var start = Math.max(
            format.channels * minSplitSamples,
            format.channels * (samples - minSplitSamples)
        );

        // For all samples at the end of the given packet, find a point where
        // the perceptible volume across all channels is lowest (and thus is
        // the optimal point to split)
        for (var offset = start; offset < data.length; offset += format.channels) {

            // Calculate the sum of all values across all channels (the result
            // will be proportional to the average volume of a sample)
            var totalValue = 0;
            for (var channel = 0; channel < format.channels; channel++) {
                totalValue += Math.abs(data[offset + channel]);
            }

            // If this is the smallest average value thus far, set the split
            // length such that the first packet ends with the current sample
            if (totalValue <= minValue) {
                optimalSplitLength = offset + format.channels;
                minValue = totalValue;
            }

        }

        // If packet is not split, return the supplied packet untouched
        if (optimalSplitLength === data.length)
            return [data];

        // Otherwise, split the packet into two new packets according to the
        // calculated optimal split length
        return [
            new SampleArray(data.buffer.slice(0, optimalSplitLength * format.bytesPerSample)),
            new SampleArray(data.buffer.slice(optimalSplitLength * format.bytesPerSample))
        ];

    };

    /**
     * Pushes the given packet of audio data onto the playback queue. Unlike
     * other private functions within Guacamole.RawAudioPlayer, the type of the
     * ArrayBuffer packet of audio data here need not be specific to the type
     * of audio (as with SampleArray). The ArrayBuffer type provided by a
     * Guacamole.ArrayBufferReader, for example, is sufficient. Any necessary
     * conversions will be performed automatically internally.
     *
     * @private
     * @param {ArrayBuffer} data
     *     A raw packet of audio data that should be pushed onto the audio
     *     playback queue.
     */
    var pushAudioPacket = function pushAudioPacket(data) {
        packetQueue.push(new SampleArray(data));
    };

    /**
     * Shifts off and returns a packet of audio data from the beginning of the
     * playback queue. The length of this audio packet is determined
     * dynamically according to the click-reduction algorithm implemented by
     * splitAudioPacket().
     *
     * @private
     * @returns {SampleArray}
     *     A packet of audio data pulled from the beginning of the playback
     *     queue.
     */
    var shiftAudioPacket = function shiftAudioPacket() {

        // Flatten data in packet queue
        var data = joinAudioPackets(packetQueue);
        if (!data)
            return null;

        // Pull an appropriate amount of data from the front of the queue
        packetQueue = splitAudioPacket(data);
        data = packetQueue.shift();

        return data;

    };

    /**
     * Converts the given audio packet into an AudioBuffer, ready for playback
     * by the Web Audio API. Unlike the raw audio packets received by this
     * audio player, AudioBuffers require floating point samples and are split
     * into isolated planes of channel-specific data.
     *
     * @private
     * @param {SampleArray} data
     *     The raw audio packet that should be converted into a Web Audio API
     *     AudioBuffer.
     *
     * @returns {AudioBuffer}
     *     A new Web Audio API AudioBuffer containing the provided audio data,
     *     converted to the format used by the Web Audio API.
     */
    var toAudioBuffer = function toAudioBuffer(data) {

        // Calculate total number of samples
        var samples = data.length / format.channels;

        // Determine exactly when packet CAN play
        var packetTime = context.currentTime;
        if (nextPacketTime < packetTime)
            nextPacketTime = packetTime;

        // Get audio buffer for specified format
        var audioBuffer = context.createBuffer(format.channels, samples, format.rate);

        // Convert each channel
        for (var channel = 0; channel < format.channels; channel++) {

            var audioData = audioBuffer.getChannelData(channel);

            // Fill audio buffer with data for channel
            var offset = channel;
            for (var i = 0; i < samples; i++) {
                audioData[i] = data[offset] / maxSampleValue;
                offset += format.channels;
            }

        }

        return audioBuffer;

    };

    // Defer playback of received audio packets slightly
    reader.ondata = function playReceivedAudio(data) {

        // Push received samples onto queue
        pushAudioPacket(new SampleArray(data));

        // Shift off an arbitrary packet of audio data from the queue (this may
        // be different in size from the packet just pushed)
        var packet = shiftAudioPacket();
        if (!packet)
            return;

        // Determine exactly when packet CAN play
        var packetTime = context.currentTime;
        if (nextPacketTime < packetTime)
            nextPacketTime = packetTime;

        // Set up buffer source
        var source = context.createBufferSource();
        source.connect(context.destination);

        // Use noteOn() instead of start() if necessary
        if (!source.start)
            source.start = source.noteOn;

        // Schedule packet
        source.buffer = toAudioBuffer(packet);
        source.start(nextPacketTime);

        // Update timeline by duration of scheduled packet
        nextPacketTime += packet.length / format.channels / format.rate;

    };

    /** @override */
    this.sync = function sync() {

        // Calculate elapsed time since last sync
        var now = context.currentTime;

        // Reschedule future playback time such that playback latency is
        // bounded within a reasonable latency threshold
        nextPacketTime = Math.min(nextPacketTime, now + maxLatency);

    };

};

Guacamole.RawAudioPlayer.prototype = new Guacamole.AudioPlayer();

/**
 * Determines whether the given mimetype is supported by
 * Guacamole.RawAudioPlayer.
 *
 * @param {String} mimetype
 *     The mimetype to check.
 *
 * @returns {Boolean}
 *     true if the given mimetype is supported by Guacamole.RawAudioPlayer,
 *     false otherwise.
 */
Guacamole.RawAudioPlayer.isSupportedType = function isSupportedType(mimetype) {

    // No supported types if no Web Audio API
    if (!Guacamole.AudioContextFactory.getAudioContext())
        return false;

    return Guacamole.RawAudioFormat.parse(mimetype) !== null;

};

/**
 * Returns a list of all mimetypes supported by Guacamole.RawAudioPlayer. Only
 * the core mimetypes themselves will be listed. Any mimetype parameters, even
 * required ones, will not be included in the list. For example, "audio/L8" is
 * a raw audio mimetype that may be supported, but it is invalid without
 * additional parameters. Something like "audio/L8;rate=44100" would be valid,
 * however (see https://tools.ietf.org/html/rfc4856).
 *
 * @returns {String[]}
 *     A list of all mimetypes supported by Guacamole.RawAudioPlayer, excluding
 *     any parameters. If the necessary JavaScript APIs for playing raw audio
 *     are absent, this list will be empty.
 */
Guacamole.RawAudioPlayer.getSupportedTypes = function getSupportedTypes() {

    // No supported types if no Web Audio API
    if (!Guacamole.AudioContextFactory.getAudioContext())
        return [];

    // We support 8-bit and 16-bit raw PCM
    return [
        'audio/L8',
        'audio/L16'
    ];

};
