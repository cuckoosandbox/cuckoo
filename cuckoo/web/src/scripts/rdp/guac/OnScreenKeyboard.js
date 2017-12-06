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
 * Dynamic on-screen keyboard. Given the layout object for an on-screen
 * keyboard, this object will construct a clickable on-screen keyboard with its
 * own key events.
 *
 * @constructor
 * @param {Guacamole.OnScreenKeyboard.Layout} layout
 *     The layout of the on-screen keyboard to display.
 */
Guacamole.OnScreenKeyboard = function(layout) {

    /**
     * Reference to this Guacamole.OnScreenKeyboard.
     *
     * @private
     * @type {Guacamole.OnScreenKeyboard}
     */
    var osk = this;

    /**
     * Map of currently-set modifiers to the keysym associated with their
     * original press. When the modifier is cleared, this keysym must be
     * released.
     *
     * @private
     * @type {Object.<String, Number>}
     */
    var modifierKeysyms = {};

    /**
     * Map of all key names to their current pressed states. If a key is not
     * pressed, it may not be in this map at all, but all pressed keys will
     * have a corresponding mapping to true.
     *
     * @private
     * @type {Object.<String, Boolean>}
     */
    var pressed = {};

    /**
     * All scalable elements which are part of the on-screen keyboard. Each
     * scalable element is carefully controlled to ensure the interface layout
     * and sizing remains constant, even on browsers that would otherwise
     * experience rounding error due to unit conversions.
     *
     * @private
     * @type {ScaledElement[]}
     */
    var scaledElements = [];

    /**
     * Adds a CSS class to an element.
     * 
     * @private
     * @function
     * @param {Element} element
     *     The element to add a class to.
     *
     * @param {String} classname
     *     The name of the class to add.
     */
    var addClass = function addClass(element, classname) {

        // If classList supported, use that
        if (element.classList)
            element.classList.add(classname);

        // Otherwise, simply append the class
        else
            element.className += " " + classname;

    };

    /**
     * Removes a CSS class from an element.
     * 
     * @private
     * @function
     * @param {Element} element
     *     The element to remove a class from.
     *
     * @param {String} classname
     *     The name of the class to remove.
     */
    var removeClass = function removeClass(element, classname) {

        // If classList supported, use that
        if (element.classList)
            element.classList.remove(classname);

        // Otherwise, manually filter out classes with given name
        else {
            element.className = element.className.replace(/([^ ]+)[ ]*/g,
                function removeMatchingClasses(match, testClassname) {

                    // If same class, remove
                    if (testClassname === classname)
                        return "";

                    // Otherwise, allow
                    return match;
                    
                }
            );
        }

    };

    /**
     * Counter of mouse events to ignore. This decremented by mousemove, and
     * while non-zero, mouse events will have no effect.
     *
     * @private
     * @type {Number}
     */
    var ignoreMouse = 0;

    /**
     * Ignores all pending mouse events when touch events are the apparent
     * source. Mouse events are ignored until at least touchMouseThreshold
     * mouse events occur without corresponding touch events.
     *
     * @private
     */
    var ignorePendingMouseEvents = function ignorePendingMouseEvents() {
        ignoreMouse = osk.touchMouseThreshold;
    };

    /**
     * An element whose dimensions are maintained according to an arbitrary
     * scale. The conversion factor for these arbitrary units to pixels is
     * provided later via a call to scale().
     *
     * @private
     * @constructor
     * @param {Element} element
     *     The element whose scale should be maintained.
     *
     * @param {Number} width
     *     The width of the element, in arbitrary units, relative to other
     *     ScaledElements.
     *
     * @param {Number} height
     *     The height of the element, in arbitrary units, relative to other
     *     ScaledElements.
     *     
     * @param {Boolean} [scaleFont=false]
     *     Whether the line height and font size should be scaled as well.
     */
    var ScaledElement = function ScaledElement(element, width, height, scaleFont) {

        /**
         * The width of this ScaledElement, in arbitrary units, relative to
         * other ScaledElements.
         *
         * @type {Number}
         */
         this.width = width;

        /**
         * The height of this ScaledElement, in arbitrary units, relative to
         * other ScaledElements.
         *
         * @type {Number}
         */
         this.height = height;
 
        /**
         * Resizes the associated element, updating its dimensions according to
         * the given pixels per unit.
         *
         * @param {Number} pixels
         *     The number of pixels to assign per arbitrary unit.
         */
        this.scale = function(pixels) {

            // Scale element width/height
            element.style.width  = (width  * pixels) + "px";
            element.style.height = (height * pixels) + "px";

            // Scale font, if requested
            if (scaleFont) {
                element.style.lineHeight = (height * pixels) + "px";
                element.style.fontSize   = pixels + "px";
            }

        };

    };

    /**
     * Returns whether all modifiers having the given names are currently
     * active.
     *
     * @private
     * @param {String[]} names
     *     The names of all modifiers to test.
     *
     * @returns {Boolean}
     *     true if all specified modifiers are pressed, false otherwise.
     */
    var modifiersPressed = function modifiersPressed(names) {

        // If any required modifiers are not pressed, return false
        for (var i=0; i < names.length; i++) {

            // Test whether current modifier is pressed
            var name = names[i];
            if (!(name in modifierKeysyms))
                return false;

        }

        // Otherwise, all required modifiers are pressed
        return true;

    };

    /**
     * Returns the single matching Key object associated with the key of the
     * given name, where that Key object's requirements (such as pressed
     * modifiers) are all currently satisfied.
     *
     * @private
     * @param {String} keyName
     *     The name of the key to retrieve.
     *
     * @returns {Guacamole.OnScreenKeyboard.Key}
     *     The Key object associated with the given name, where that object's
     *     requirements are all currently satisfied, or null if no such Key
     *     can be found.
     */
    var getActiveKey = function getActiveKey(keyName) {

        // Get key array for given name
        var keys = osk.keys[keyName];
        if (!keys)
            return null;

        // Find last matching key
        for (var i = keys.length - 1; i >= 0; i--) {

            // Get candidate key
            var candidate = keys[i];

            // If all required modifiers are pressed, use that key
            if (modifiersPressed(candidate.requires))
                return candidate;

        }

        // No valid key
        return null;

    };

    /**
     * Presses the key having the given name, updating the associated key
     * element with the "guac-keyboard-pressed" CSS class. If the key is
     * already pressed, this function has no effect.
     *
     * @private
     * @param {String} keyName
     *     The name of the key to press.
     *
     * @param {String} keyElement
     *     The element associated with the given key.
     */
    var press = function press(keyName, keyElement) {

        // Press key if not yet pressed
        if (!pressed[keyName]) {

            addClass(keyElement, "guac-keyboard-pressed");

            // Get current key based on modifier state
            var key = getActiveKey(keyName);

            // Update modifier state
            if (key.modifier) {

                // Construct classname for modifier
                var modifierClass = "guac-keyboard-modifier-" + getCSSName(key.modifier);

                // Retrieve originally-pressed keysym, if modifier was already pressed
                var originalKeysym = modifierKeysyms[key.modifier];

                // Activate modifier if not pressed
                if (!originalKeysym) {
                    
                    addClass(keyboard, modifierClass);
                    modifierKeysyms[key.modifier] = key.keysym;
                    
                    // Send key event
                    if (osk.onkeydown)
                        osk.onkeydown(key.keysym);

                }

                // Deactivate if not pressed
                else {

                    removeClass(keyboard, modifierClass);
                    delete modifierKeysyms[key.modifier];
                    
                    // Send key event
                    if (osk.onkeyup)
                        osk.onkeyup(originalKeysym);

                }

            }

            // If not modifier, send key event now
            else if (osk.onkeydown)
                osk.onkeydown(key.keysym);

            // Mark key as pressed
            pressed[keyName] = true;

        }

    };

    /**
     * Releases the key having the given name, removing the
     * "guac-keyboard-pressed" CSS class from the associated element. If the
     * key is already released, this function has no effect.
     *
     * @private
     * @param {String} keyName
     *     The name of the key to release.
     *
     * @param {String} keyElement
     *     The element associated with the given key.
     */
    var release = function release(keyName, keyElement) {

        // Release key if currently pressed
        if (pressed[keyName]) {

            removeClass(keyElement, "guac-keyboard-pressed");

            // Get current key based on modifier state
            var key = getActiveKey(keyName);

            // Send key event if not a modifier key
            if (!key.modifier && osk.onkeyup)
                osk.onkeyup(key.keysym);

            // Mark key as released
            pressed[keyName] = false;

        }

    };

    // Create keyboard
    var keyboard = document.createElement("div");
    keyboard.className = "guac-keyboard";

    // Do not allow selection or mouse movement to propagate/register.
    keyboard.onselectstart =
    keyboard.onmousemove   =
    keyboard.onmouseup     =
    keyboard.onmousedown   = function handleMouseEvents(e) {

        // If ignoring events, decrement counter
        if (ignoreMouse)
            ignoreMouse--;

        e.stopPropagation();
        return false;

    };

    /**
     * The number of mousemove events to require before re-enabling mouse
     * event handling after receiving a touch event.
     *
     * @type {Number}
     */
    this.touchMouseThreshold = 3;

    /**
     * Fired whenever the user presses a key on this Guacamole.OnScreenKeyboard.
     * 
     * @event
     * @param {Number} keysym The keysym of the key being pressed.
     */
    this.onkeydown = null;

    /**
     * Fired whenever the user releases a key on this Guacamole.OnScreenKeyboard.
     * 
     * @event
     * @param {Number} keysym The keysym of the key being released.
     */
    this.onkeyup = null;

    /**
     * The keyboard layout provided at time of construction.
     *
     * @type {Guacamole.OnScreenKeyboard.Layout}
     */
    this.layout = new Guacamole.OnScreenKeyboard.Layout(layout);

    /**
     * Returns the element containing the entire on-screen keyboard.
     * @returns {Element} The element containing the entire on-screen keyboard.
     */
    this.getElement = function() {
        return keyboard;
    };

    /**
     * Resizes all elements within this Guacamole.OnScreenKeyboard such that
     * the width is close to but does not exceed the specified width. The
     * height of the keyboard is determined based on the width.
     * 
     * @param {Number} width The width to resize this Guacamole.OnScreenKeyboard
     *                       to, in pixels.
     */
    this.resize = function(width) {

        // Get pixel size of a unit
        var unit = Math.floor(width * 10 / osk.layout.width) / 10;

        // Resize all scaled elements
        for (var i=0; i<scaledElements.length; i++) {
            var scaledElement = scaledElements[i];
            scaledElement.scale(unit);
        }

    };

    /**
     * Given the name of a key and its corresponding definition, which may be
     * an array of keys objects, a number (keysym), a string (key title), or a
     * single key object, returns an array of key objects, deriving any missing
     * properties as needed, and ensuring the key name is defined.
     *
     * @private
     * @param {String} name
     *     The name of the key being coerced into an array of Key objects.
     *
     * @param {Number|String|Guacamole.OnScreenKeyboard.Key|Guacamole.OnScreenKeyboard.Key[]} object
     *     The object defining the behavior of the key having the given name,
     *     which may be the title of the key (a string), the keysym (a number),
     *     a single Key object, or an array of Key objects.
     *     
     * @returns {Guacamole.OnScreenKeyboard.Key[]}
     *     An array of all keys associated with the given name.
     */
    var asKeyArray = function asKeyArray(name, object) {

        // If already an array, just coerce into a true Key[] 
        if (object instanceof Array) {
            var keys = [];
            for (var i=0; i < object.length; i++) {
                keys.push(new Guacamole.OnScreenKeyboard.Key(object[i], name));
            }
            return keys;
        }

        // Derive key object from keysym if that's all we have
        if (typeof object === 'number') {
            return [new Guacamole.OnScreenKeyboard.Key({
                name   : name,
                keysym : object
            })];
        }

        // Derive key object from title if that's all we have
        if (typeof object === 'string') {
            return [new Guacamole.OnScreenKeyboard.Key({
                name  : name,
                title : object
            })];
        }

        // Otherwise, assume it's already a key object, just not an array
        return [new Guacamole.OnScreenKeyboard.Key(object, name)];

    };

    /**
     * Converts the rather forgiving key mapping allowed by
     * Guacamole.OnScreenKeyboard.Layout into a rigorous mapping of key name
     * to key definition, where the key definition is always an array of Key
     * objects.
     *
     * @private
     * @param {Object.<String, Number|String|Guacamole.OnScreenKeyboard.Key|Guacamole.OnScreenKeyboard.Key[]>} keys
     *     A mapping of key name to key definition, where the key definition is
     *     the title of the key (a string), the keysym (a number), a single
     *     Key object, or an array of Key objects.
     *
     * @returns {Object.<String, Guacamole.OnScreenKeyboard.Key[]>}
     *     A more-predictable mapping of key name to key definition, where the
     *     key definition is always simply an array of Key objects.
     */
    var getKeys = function getKeys(keys) {

        var keyArrays = {};

        // Coerce all keys into individual key arrays
        for (var name in layout.keys) {
            keyArrays[name] = asKeyArray(name, keys[name]);
        }

        return keyArrays;

    };

    /**
     * Map of all key names to their corresponding set of keys. Each key name
     * may correspond to multiple keys due to the effect of modifiers.
     *
     * @type {Object.<String, Guacamole.OnScreenKeyboard.Key[]>}
     */
    this.keys = getKeys(layout.keys);

    /**
     * Given an arbitrary string representing the name of some component of the
     * on-screen keyboard, returns a string formatted for use as a CSS class
     * name. The result will be lowercase. Word boundaries previously denoted
     * by CamelCase will be replaced by individual hyphens, as will all
     * contiguous non-alphanumeric characters.
     *
     * @private
     * @param {String} name
     *     An arbitrary string representing the name of some component of the
     *     on-screen keyboard.
     *
     * @returns {String}
     *     A string formatted for use as a CSS class name.
     */
    var getCSSName = function getCSSName(name) {

        // Convert name from possibly-CamelCase to hyphenated lowercase
        var cssName = name
               .replace(/([a-z])([A-Z])/g, '$1-$2')
               .replace(/[^A-Za-z0-9]+/g, '-')
               .toLowerCase();

        return cssName;

    };

    /**
     * Appends DOM elements to the given element as dictated by the layout
     * structure object provided. If a name is provided, an additional CSS
     * class, prepended with "guac-keyboard-", will be added to the top-level
     * element.
     * 
     * If the layout structure object is an array, all elements within that
     * array will be recursively appended as children of a group, and the
     * top-level element will be given the CSS class "guac-keyboard-group".
     *
     * If the layout structure object is an object, all properties within that
     * object will be recursively appended as children of a group, and the
     * top-level element will be given the CSS class "guac-keyboard-group". The
     * name of each property will be applied as the name of each child object
     * for the sake of CSS. Each property will be added in sorted order.
     *
     * If the layout structure object is a string, the key having that name
     * will be appended. The key will be given the CSS class
     * "guac-keyboard-key" and "guac-keyboard-key-NAME", where NAME is the name
     * of the key. If the name of the key is a single character, this will
     * first be transformed into the C-style hexadecimal literal for the
     * Unicode codepoint of that character. For example, the key "A" would
     * become "guac-keyboard-key-0x41".
     * 
     * If the layout structure object is a number, a gap of that size will be
     * inserted. The gap will be given the CSS class "guac-keyboard-gap", and
     * will be scaled according to the same size units as each key.
     *
     * @private
     * @param {Element} element
     *     The element to append elements to.
     *
     * @param {Array|Object|String|Number} object
     *     The layout structure object to use when constructing the elements to
     *     append.
     *
     * @param {String} [name]
     *     The name of the top-level element being appended, if any.
     */
    var appendElements = function appendElements(element, object, name) {

        var i;

        // Create div which will become the group or key
        var div = document.createElement('div');

        // Add class based on name, if name given
        if (name)
            addClass(div, 'guac-keyboard-' + getCSSName(name));

        // If an array, append each element
        if (object instanceof Array) {

            // Add group class
            addClass(div, 'guac-keyboard-group');

            // Append all elements of array
            for (i=0; i < object.length; i++)
                appendElements(div, object[i]);

        }

        // If an object, append each property value
        else if (object instanceof Object) {

            // Add group class
            addClass(div, 'guac-keyboard-group');

            // Append all children, sorted by name
            var names = Object.keys(object).sort();
            for (i=0; i < names.length; i++) {
                var name = names[i];
                appendElements(div, object[name], name);
            }

        }

        // If a number, create as a gap 
        else if (typeof object === 'number') {

            // Add gap class
            addClass(div, 'guac-keyboard-gap');

            // Maintain scale
            scaledElements.push(new ScaledElement(div, object, object));

        }

        // If a string, create as a key
        else if (typeof object === 'string') {

            // If key name is only one character, use codepoint for name
            var keyName = object;
            if (keyName.length === 1)
                keyName = '0x' + keyName.charCodeAt(0).toString(16);

            // Add key container class
            addClass(div, 'guac-keyboard-key-container');

            // Create key element which will contain all possible caps
            var keyElement = document.createElement('div');
            keyElement.className = 'guac-keyboard-key '
                                 + 'guac-keyboard-key-' + getCSSName(keyName);

            // Add all associated keys as caps within DOM
            var keys = osk.keys[object];
            if (keys) {
                for (i=0; i < keys.length; i++) {

                    // Get current key
                    var key = keys[i];

                    // Create cap element for key
                    var capElement = document.createElement('div');
                    capElement.className   = 'guac-keyboard-cap';
                    capElement.textContent = key.title;

                    // Add classes for any requirements
                    for (var j=0; j < key.requires.length; j++) {
                        var requirement = key.requires[j];
                        addClass(capElement, 'guac-keyboard-requires-' + getCSSName(requirement));
                        addClass(keyElement, 'guac-keyboard-uses-'     + getCSSName(requirement));
                    }

                    // Add cap to key within DOM
                    keyElement.appendChild(capElement);

                }
            }

            // Add key to DOM, maintain scale
            div.appendChild(keyElement);
            scaledElements.push(new ScaledElement(div, osk.layout.keyWidths[object] || 1, 1, true));

            /**
             * Handles a touch event which results in the pressing of an OSK
             * key. Touch events will result in mouse events being ignored for
             * touchMouseThreshold events.
             *
             * @private
             * @param {TouchEvent} e
             *     The touch event being handled.
             */
            var touchPress = function touchPress(e) {
                e.preventDefault();
                ignoreMouse = osk.touchMouseThreshold;
                press(object, keyElement);
            };

            /**
             * Handles a touch event which results in the release of an OSK
             * key. Touch events will result in mouse events being ignored for
             * touchMouseThreshold events.
             *
             * @private
             * @param {TouchEvent} e
             *     The touch event being handled.
             */
            var touchRelease = function touchRelease(e) {
                e.preventDefault();
                ignoreMouse = osk.touchMouseThreshold;
                release(object, keyElement);
            };

            /**
             * Handles a mouse event which results in the pressing of an OSK
             * key. If mouse events are currently being ignored, this handler
             * does nothing.
             *
             * @private
             * @param {MouseEvent} e
             *     The touch event being handled.
             */
            var mousePress = function mousePress(e) {
                e.preventDefault();
                if (ignoreMouse === 0)
                    press(object, keyElement);
            };

            /**
             * Handles a mouse event which results in the release of an OSK
             * key. If mouse events are currently being ignored, this handler
             * does nothing.
             *
             * @private
             * @param {MouseEvent} e
             *     The touch event being handled.
             */
            var mouseRelease = function mouseRelease(e) {
                e.preventDefault();
                if (ignoreMouse === 0)
                    release(object, keyElement);
            };

            // Handle touch events on key
            keyElement.addEventListener("touchstart", touchPress,   true);
            keyElement.addEventListener("touchend",   touchRelease, true);

            // Handle mouse events on key
            keyElement.addEventListener("mousedown", mousePress,   true);
            keyElement.addEventListener("mouseup",   mouseRelease, true);
            keyElement.addEventListener("mouseout",  mouseRelease, true);

        } // end if object is key name

        // Add newly-created group/key
        element.appendChild(div);

    };

    // Create keyboard layout in DOM
    appendElements(keyboard, layout.layout);

};

/**
 * Represents an entire on-screen keyboard layout, including all available
 * keys, their behaviors, and their relative position and sizing.
 *
 * @constructor
 * @param {Guacamole.OnScreenKeyboard.Layout|Object} template
 *     The object whose identically-named properties will be used to initialize
 *     the properties of this layout.
 */
Guacamole.OnScreenKeyboard.Layout = function(template) {

    /**
     * The language of keyboard layout, such as "en_US". This property is for
     * informational purposes only, but it is recommend to conform to the
     * [language code]_[country code] format.
     *
     * @type {String}
     */
    this.language = template.language;

    /**
     * The type of keyboard layout, such as "qwerty". This property is for
     * informational purposes only, and does not conform to any standard.
     *
     * @type {String}
     */
    this.type = template.type;

    /**
     * Map of key name to corresponding keysym, title, or key object. If only
     * the keysym or title is provided, the key object will be created
     * implicitly. In all cases, the name property of the key object will be
     * taken from the name given in the mapping.
     *
     * @type {Object.<String, Number|String|Guacamole.OnScreenKeyboard.Key|Guacamole.OnScreenKeyboard.Key[]>}
     */
    this.keys = template.keys;

    /**
     * Arbitrarily nested, arbitrarily grouped key names. The contents of the
     * layout will be traversed to produce an identically-nested grouping of
     * keys in the DOM tree. All strings will be transformed into their
     * corresponding sets of keys, while all objects and arrays will be
     * transformed into named groups and anonymous groups respectively. Any
     * numbers present will be transformed into gaps of that size, scaled
     * according to the same units as each key.
     *
     * @type {Object}
     */
    this.layout = template.layout;

    /**
     * The width of the entire keyboard, in arbitrary units. The width of each
     * key is relative to this width, as both width values are assumed to be in
     * the same units. The conversion factor between these units and pixels is
     * derived later via a call to resize() on the Guacamole.OnScreenKeyboard.
     *
     * @type {Number}
     */
    this.width = template.width;

    /**
     * The width of each key, in arbitrary units, relative to other keys in
     * this layout. The true pixel size of each key will be determined by the
     * overall size of the keyboard. If not defined here, the width of each
     * key will default to 1.
     *
     * @type {Object.<String, Number>}
     */
    this.keyWidths = template.keyWidths || {};

};

/**
 * Represents a single key, or a single possible behavior of a key. Each key
 * on the on-screen keyboard must have at least one associated
 * Guacamole.OnScreenKeyboard.Key, whether that key is explicitly defined or
 * implied, and may have multiple Guacamole.OnScreenKeyboard.Key if behavior
 * depends on modifier states.
 *
 * @constructor
 * @param {Guacamole.OnScreenKeyboard.Key|Object} template
 *     The object whose identically-named properties will be used to initialize
 *     the properties of this key.
 *     
 * @param {String} [name]
 *     The name to use instead of any name provided within the template, if
 *     any. If omitted, the name within the template will be used, assuming the
 *     template contains a name.
 */
Guacamole.OnScreenKeyboard.Key = function(template, name) {

    /**
     * The unique name identifying this key within the keyboard layout.
     *
     * @type {String}
     */
    this.name = name || template.name;

    /**
     * The human-readable title that will be displayed to the user within the
     * key. If not provided, this will be derived from the key name.
     *
     * @type {String}
     */
    this.title = template.title || this.name;

    /**
     * The keysym to be pressed/released when this key is pressed/released. If
     * not provided, this will be derived from the title if the title is a
     * single character.
     *
     * @type {Number}
     */
    this.keysym = template.keysym || (function deriveKeysym(title) {

        // Do not derive keysym if title is not exactly one character
        if (!title || title.length !== 1)
            return null;

        // For characters between U+0000 and U+00FF, the keysym is the codepoint
        var charCode = title.charCodeAt(0);
        if (charCode >= 0x0000 && charCode <= 0x00FF)
            return charCode;

        // For characters between U+0100 and U+10FFFF, the keysym is the codepoint or'd with 0x01000000
        if (charCode >= 0x0100 && charCode <= 0x10FFFF)
            return 0x01000000 | charCode;

        // Unable to derive keysym
        return null;

    })(this.title);

    /**
     * The name of the modifier set when the key is pressed and cleared when
     * this key is released, if any. The names of modifiers are distinct from
     * the names of keys; both the "RightShift" and "LeftShift" keys may set
     * the "shift" modifier, for example. By default, the key will affect no
     * modifiers.
     * 
     * @type {String}
     */
    this.modifier = template.modifier;

    /**
     * An array containing the names of each modifier required for this key to
     * have an effect. For example, a lowercase letter may require nothing,
     * while an uppercase letter would require "shift", assuming the Shift key
     * is named "shift" within the layout. By default, the key will require
     * no modifiers.
     *
     * @type {String[]}
     */
    this.requires = template.requires || [];

};
