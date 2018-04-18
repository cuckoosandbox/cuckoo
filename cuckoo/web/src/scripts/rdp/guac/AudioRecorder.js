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
 * Abstract audio recorder which streams arbitrary audio data to an underlying
 * Guacamole.OutputStream. It is up to implementations of this class to provide
 * some means of handling this Guacamole.OutputStream. Data produced by the
 * recorder is to be sent along the provided stream immediately.
 *
 * @constructor
 */
Guacamole.AudioRecorder = function AudioRecorder() {

    /**
     * Callback which is invoked when the audio recording process has stopped
     * and the underlying Guacamole stream has been closed normally. Audio will
     * only resume recording if a new Guacamole.AudioRecorder is started. This
     * Guacamole.AudioRecorder instance MAY NOT be reused.
     *
     * @event
     */
    this.onclose = null;

    /**
     * Callback which is invoked when the audio recording process cannot
     * continue due to an error, if it has started at all. The underlying
     * Guacamole stream is automatically closed. Future attempts to record
     * audio should not be made, and this Guacamole.AudioRecorder instance
     * MAY NOT be reused.
     *
     * @event
     */
    this.onerror = null;

};

/**
 * Determines whether the given mimetype is supported by any built-in
 * implementation of Guacamole.AudioRecorder, and thus will be properly handled
 * by Guacamole.AudioRecorder.getInstance().
 *
 * @param {String} mimetype
 *     The mimetype to check.
 *
 * @returns {Boolean}
 *     true if the given mimetype is supported by any built-in
 *     Guacamole.AudioRecorder, false otherwise.
 */
Guacamole.AudioRecorder.isSupportedType = function isSupportedType(mimetype) {

    return Guacamole.RawAudioRecorder.isSupportedType(mimetype);

};

/**
 * Returns a list of all mimetypes supported by any built-in
 * Guacamole.AudioRecorder, in rough order of priority. Beware that only the
 * core mimetypes themselves will be listed. Any mimetype parameters, even
 * required ones, will not be included in the list. For example, "audio/L8" is
 * a supported raw audio mimetype that is supported, but it is invalid without
 * additional parameters. Something like "audio/L8;rate=44100" would be valid,
 * however (see https://tools.ietf.org/html/rfc4856).
 *
 * @returns {String[]}
 *     A list of all mimetypes supported by any built-in
 *     Guacamole.AudioRecorder, excluding any parameters.
 */
Guacamole.AudioRecorder.getSupportedTypes = function getSupportedTypes() {

    return Guacamole.RawAudioRecorder.getSupportedTypes();

};

/**
 * Returns an instance of Guacamole.AudioRecorder providing support for the
 * given audio format. If support for the given audio format is not available,
 * null is returned.
 *
 * @param {Guacamole.OutputStream} stream
 *     The Guacamole.OutputStream to send audio data through.
 *
 * @param {String} mimetype
 *     The mimetype of the audio data to be sent along the provided stream.
 *
 * @return {Guacamole.AudioRecorder}
 *     A Guacamole.AudioRecorder instance supporting the given mimetype and
 *     writing to the given stream, or null if support for the given mimetype
 *     is absent.
 */
Guacamole.AudioRecorder.getInstance = function getInstance(stream, mimetype) {

    // Use raw audio recorder if possible
    if (Guacamole.RawAudioRecorder.isSupportedType(mimetype))
        return new Guacamole.RawAudioRecorder(stream, mimetype);

    // No support for given mimetype
    return null;

};

/**
 * Implementation of Guacamole.AudioRecorder providing support for raw PCM
 * format audio. This recorder relies only on the Web Audio API and does not
 * require any browser-level support for its audio formats.
 *
 * @constructor
 * @augments Guacamole.AudioRecorder
 * @param {Guacamole.OutputStream} stream
 *     The Guacamole.OutputStream to write audio data to.
 *
 * @param {String} mimetype
 *     The mimetype of the audio data to send along the provided stream, which
 *     must be a "audio/L8" or "audio/L16" mimetype with necessary parameters,
 *     such as: "audio/L16;rate=44100,channels=2".
 */
Guacamole.RawAudioRecorder = function RawAudioRecorder(stream, mimetype) {

    /**
     * Reference to this RawAudioRecorder.
     *
     * @private
     * @type {Guacamole.RawAudioRecorder}
     */
    var recorder = this;

    /**
     * The size of audio buffer to request from the Web Audio API when
     * recording or processing audio, in sample-frames. This must be a power of
     * two between 256 and 16384 inclusive, as required by
     * AudioContext.createScriptProcessor().
     *
     * @private
     * @constant
     * @type {Number}
     */
    var BUFFER_SIZE = 2048;

    /**
     * The window size to use when applying Lanczos interpolation, commonly
     * denoted by the variable "a".
     * See: https://en.wikipedia.org/wiki/Lanczos_resampling
     *
     * @private
     * @contant
     * @type Number
     */
    var LANCZOS_WINDOW_SIZE = 3;

    /**
     * The format of audio this recorder will encode.
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
     * A function which directly invokes the browser's implementation of
     * navigator.getUserMedia() with all provided parameters.
     *
     * @type Function
     */
    var getUserMedia = (navigator.getUserMedia
            || navigator.webkitGetUserMedia
            || navigator.mozGetUserMedia
            || navigator.msGetUserMedia).bind(navigator);

    /**
     * Guacamole.ArrayBufferWriter wrapped around the audio output stream
     * provided when this Guacamole.RawAudioRecorder was created.
     *
     * @private
     * @type {Guacamole.ArrayBufferWriter}
     */
    var writer = new Guacamole.ArrayBufferWriter(stream);

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
     * The maximum absolute value of any sample within a raw audio packet sent
     * by this audio recorder. This depends only on the size of each sample,
     * and will be 128 for 8-bit audio and 32768 for 16-bit audio.
     *
     * @private
     * @type {Number}
     */
    var maxSampleValue = (format.bytesPerSample === 1) ? 128 : 32768;

    /**
     * The total number of audio samples read from the local audio input device
     * over the life of this audio recorder.
     *
     * @private
     * @type {Number}
     */
    var readSamples = 0;

    /**
     * The total number of audio samples written to the underlying Guacamole
     * connection over the life of this audio recorder.
     *
     * @private
     * @type {Number}
     */
    var writtenSamples = 0;

    /**
     * The audio stream provided by the browser, if allowed. If no stream has
     * yet been received, this will be null.
     *
     * @type MediaStream
     */
    var mediaStream = null;

    /**
     * The source node providing access to the local audio input device.
     *
     * @private
     * @type {MediaStreamAudioSourceNode}
     */
    var source = null;

    /**
     * The script processing node which receives audio input from the media
     * stream source node as individual audio buffers.
     *
     * @private
     * @type {ScriptProcessorNode}
     */
    var processor = null;

    /**
     * The normalized sinc function. The normalized sinc function is defined as
     * 1 for x=0 and sin(PI * x) / (PI * x) for all other values of x.
     *
     * See: https://en.wikipedia.org/wiki/Sinc_function
     *
     * @private
     * @param {Number} x
     *     The point at which the normalized sinc function should be computed.
     *
     * @returns {Number}
     *     The value of the normalized sinc function at x.
     */
    var sinc = function sinc(x) {

        // The value of sinc(0) is defined as 1
        if (x === 0)
            return 1;

        // Otherwise, normlized sinc(x) is sin(PI * x) / (PI * x)
        var piX = Math.PI * x;
        return Math.sin(piX) / piX;

    };

    /**
     * Calculates the value of the Lanczos kernal at point x for a given window
     * size. See: https://en.wikipedia.org/wiki/Lanczos_resampling
     *
     * @private
     * @param {Number} x
     *     The point at which the value of the Lanczos kernel should be
     *     computed.
     *
     * @param {Number} a
     *     The window size to use for the Lanczos kernel.
     *
     * @returns {Number}
     *     The value of the Lanczos kernel at the given point for the given
     *     window size.
     */
    var lanczos = function lanczos(x, a) {

        // Lanczos is sinc(x) * sinc(x / a) for -a < x < a ...
        if (-a < x && x < a)
            return sinc(x) * sinc(x / a);

        // ... and 0 otherwise
        return 0;

    };

    /**
     * Determines the value of the waveform represented by the audio data at
     * the given location. If the value cannot be determined exactly as it does
     * not correspond to an exact sample within the audio data, the value will
     * be derived through interpolating nearby samples.
     *
     * @private
     * @param {Float32Array} audioData
     *     An array of audio data, as returned by AudioBuffer.getChannelData().
     *
     * @param {Number} t
     *     The relative location within the waveform from which the value
     *     should be retrieved, represented as a floating point number between
     *     0 and 1 inclusive, where 0 represents the earliest point in time and
     *     1 represents the latest.
     *
     * @returns {Number}
     *     The value of the waveform at the given location.
     */
    var interpolateSample = function getValueAt(audioData, t) {

        // Convert [0, 1] range to [0, audioData.length - 1]
        var index = (audioData.length - 1) * t;

        // Determine the start and end points for the summation used by the
        // Lanczos interpolation algorithm (see: https://en.wikipedia.org/wiki/Lanczos_resampling)
        var start = Math.floor(index) - LANCZOS_WINDOW_SIZE + 1;
        var end = Math.floor(index) + LANCZOS_WINDOW_SIZE;

        // Calculate the value of the Lanczos interpolation function for the
        // required range
        var sum = 0;
        for (var i = start; i <= end; i++) {
            sum += (audioData[i] || 0) * lanczos(index - i, LANCZOS_WINDOW_SIZE);
        }

        return sum;

    };

    /**
     * Converts the given AudioBuffer into an audio packet, ready for streaming
     * along the underlying output stream. Unlike the raw audio packets used by
     * this audio recorder, AudioBuffers require floating point samples and are
     * split into isolated planes of channel-specific data.
     *
     * @private
     * @param {AudioBuffer} audioBuffer
     *     The Web Audio API AudioBuffer that should be converted to a raw
     *     audio packet.
     *
     * @returns {SampleArray}
     *     A new raw audio packet containing the audio data from the provided
     *     AudioBuffer.
     */
    var toSampleArray = function toSampleArray(audioBuffer) {

        // Track overall amount of data read
        var inSamples = audioBuffer.length;
        readSamples += inSamples;

        // Calculate the total number of samples that should be written as of
        // the audio data just received and adjust the size of the output
        // packet accordingly
        var expectedWrittenSamples = Math.round(readSamples * format.rate / audioBuffer.sampleRate);
        var outSamples = expectedWrittenSamples - writtenSamples;

        // Update number of samples written
        writtenSamples += outSamples;

        // Get array for raw PCM storage
        var data = new SampleArray(outSamples * format.channels);

        // Convert each channel
        for (var channel = 0; channel < format.channels; channel++) {

            var audioData = audioBuffer.getChannelData(channel);

            // Fill array with data from audio buffer channel
            var offset = channel;
            for (var i = 0; i < outSamples; i++) {
                data[offset] = interpolateSample(audioData, i / (outSamples - 1)) * maxSampleValue;
                offset += format.channels;
            }

        }

        return data;

    };

    /**
     * Requests access to the user's microphone and begins capturing audio. All
     * received audio data is resampled as necessary and forwarded to the
     * Guacamole stream underlying this Guacamole.RawAudioRecorder. This
     * function must be invoked ONLY ONCE per instance of
     * Guacamole.RawAudioRecorder.
     *
     * @private
     */
    var beginAudioCapture = function beginAudioCapture() {

        // Attempt to retrieve an audio input stream from the browser
        getUserMedia({ 'audio' : true }, function streamReceived(stream) {

            // Create processing node which receives appropriately-sized audio buffers
            processor = context.createScriptProcessor(BUFFER_SIZE, format.channels, format.channels);
            processor.connect(context.destination);

            // Send blobs when audio buffers are received
            processor.onaudioprocess = function processAudio(e) {
                writer.sendData(toSampleArray(e.inputBuffer).buffer);
            };

            // Connect processing node to user's audio input source
            source = context.createMediaStreamSource(stream);
            source.connect(processor);

            // Save stream for later cleanup
            mediaStream = stream;

        }, function streamDenied() {

            // Simply end stream if audio access is not allowed
            writer.sendEnd();

            // Notify of closure
            if (recorder.onerror)
                recorder.onerror();

        });

    };

    /**
     * Stops capturing audio, if the capture has started, freeing all associated
     * resources. If the capture has not started, this function simply ends the
     * underlying Guacamole stream.
     *
     * @private
     */
    var stopAudioCapture = function stopAudioCapture() {

        // Disconnect media source node from script processor
        if (source)
            source.disconnect();

        // Disconnect associated script processor node
        if (processor)
            processor.disconnect();

        // Stop capture
        if (mediaStream) {
            var tracks = mediaStream.getTracks();
            for (var i = 0; i < tracks.length; i++)
                tracks[i].stop();
        }

        // Remove references to now-unneeded components
        processor = null;
        source = null;
        mediaStream = null;

        // End stream
        writer.sendEnd();

    };

    // Once audio stream is successfully open, request and begin reading audio
    writer.onack = function audioStreamAcknowledged(status) {

        // Begin capture if successful response and not yet started
        if (status.code === Guacamole.Status.Code.SUCCESS && !mediaStream)
            beginAudioCapture();

        // Otherwise stop capture and cease handling any further acks
        else {

            // Stop capturing audio
            stopAudioCapture();
            writer.onack = null;

            // Notify if stream has closed normally
            if (status.code === Guacamole.Status.Code.RESOURCE_CLOSED) {
                if (recorder.onclose)
                    recorder.onclose();
            }

            // Otherwise notify of closure due to error
            else {
                if (recorder.onerror)
                    recorder.onerror();
            }

        }

    };

};

Guacamole.RawAudioRecorder.prototype = new Guacamole.AudioRecorder();

/**
 * Determines whether the given mimetype is supported by
 * Guacamole.RawAudioRecorder.
 *
 * @param {String} mimetype
 *     The mimetype to check.
 *
 * @returns {Boolean}
 *     true if the given mimetype is supported by Guacamole.RawAudioRecorder,
 *     false otherwise.
 */
Guacamole.RawAudioRecorder.isSupportedType = function isSupportedType(mimetype) {

    // No supported types if no Web Audio API
    if (!Guacamole.AudioContextFactory.getAudioContext())
        return false;

    return Guacamole.RawAudioFormat.parse(mimetype) !== null;

};

/**
 * Returns a list of all mimetypes supported by Guacamole.RawAudioRecorder. Only
 * the core mimetypes themselves will be listed. Any mimetype parameters, even
 * required ones, will not be included in the list. For example, "audio/L8" is
 * a raw audio mimetype that may be supported, but it is invalid without
 * additional parameters. Something like "audio/L8;rate=44100" would be valid,
 * however (see https://tools.ietf.org/html/rfc4856).
 *
 * @returns {String[]}
 *     A list of all mimetypes supported by Guacamole.RawAudioRecorder,
 *     excluding any parameters. If the necessary JavaScript APIs for recording
 *     raw audio are absent, this list will be empty.
 */
Guacamole.RawAudioRecorder.getSupportedTypes = function getSupportedTypes() {

    // No supported types if no Web Audio API
    if (!Guacamole.AudioContextFactory.getAudioContext())
        return [];

    // We support 8-bit and 16-bit raw PCM
    return [
        'audio/L8',
        'audio/L16'
    ];

};
