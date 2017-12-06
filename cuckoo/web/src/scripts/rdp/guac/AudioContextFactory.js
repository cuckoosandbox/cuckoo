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
 * Maintains a singleton instance of the Web Audio API AudioContext class,
 * instantiating the AudioContext only in response to the first call to
 * getAudioContext(), and only if no existing AudioContext instance has been
 * provided via the singleton property. Subsequent calls to getAudioContext()
 * will return the same instance.
 *
 * @namespace
 */
Guacamole.AudioContextFactory = {

    /**
     * A singleton instance of a Web Audio API AudioContext object, or null if
     * no instance has yes been created. This property may be manually set if
     * you wish to supply your own AudioContext instance, but care must be
     * taken to do so as early as possible. Assignments to this property will
     * not retroactively affect the value returned by previous calls to
     * getAudioContext().
     *
     * @type {AudioContext}
     */
    'singleton' : null,

    /**
     * Returns a singleton instance of a Web Audio API AudioContext object.
     *
     * @return {AudioContext}
     *     A singleton instance of a Web Audio API AudioContext object, or null
     *     if the Web Audio API is not supported.
     */
    'getAudioContext' : function getAudioContext() {

        // Fallback to Webkit-specific AudioContext implementation
        var AudioContext = window.AudioContext || window.webkitAudioContext;

        // Get new AudioContext instance if Web Audio API is supported
        if (AudioContext) {
            try {

                // Create new instance if none yet exists
                if (!Guacamole.AudioContextFactory.singleton)
                    Guacamole.AudioContextFactory.singleton = new AudioContext();

                // Return singleton instance
                return Guacamole.AudioContextFactory.singleton;

            }
            catch (e) {
                // Do not use Web Audio API if not allowed by browser
            }
        }

        // Web Audio API not supported
        return null;

    }

};
