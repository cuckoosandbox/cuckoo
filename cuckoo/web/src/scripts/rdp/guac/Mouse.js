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
 * Provides cross-browser mouse events for a given element. The events of
 * the given element are automatically populated with handlers that translate
 * mouse events into a non-browser-specific event provided by the
 * Guacamole.Mouse instance.
 * 
 * @constructor
 * @param {Element} element The Element to use to provide mouse events.
 */
Guacamole.Mouse = function(element) {

    /**
     * Reference to this Guacamole.Mouse.
     * @private
     */
    var guac_mouse = this;

    /**
     * The number of mousemove events to require before re-enabling mouse
     * event handling after receiving a touch event.
     */
    this.touchMouseThreshold = 3;

    /**
     * The minimum amount of pixels scrolled required for a single scroll button
     * click.
     */
    this.scrollThreshold = 53;

    /**
     * The number of pixels to scroll per line.
     */
    this.PIXELS_PER_LINE = 18;

    /**
     * The number of pixels to scroll per page.
     */
    this.PIXELS_PER_PAGE = this.PIXELS_PER_LINE * 16;

    /**
     * The current mouse state. The properties of this state are updated when
     * mouse events fire. This state object is also passed in as a parameter to
     * the handler of any mouse events.
     * 
     * @type {Guacamole.Mouse.State}
     */
    this.currentState = new Guacamole.Mouse.State(
        0, 0, 
        false, false, false, false, false
    );

    /**
     * Fired whenever the user presses a mouse button down over the element
     * associated with this Guacamole.Mouse.
     * 
     * @event
     * @param {Guacamole.Mouse.State} state The current mouse state.
     */
	this.onmousedown = null;

    /**
     * Fired whenever the user releases a mouse button down over the element
     * associated with this Guacamole.Mouse.
     * 
     * @event
     * @param {Guacamole.Mouse.State} state The current mouse state.
     */
	this.onmouseup = null;

    /**
     * Fired whenever the user moves the mouse over the element associated with
     * this Guacamole.Mouse.
     * 
     * @event
     * @param {Guacamole.Mouse.State} state The current mouse state.
     */
	this.onmousemove = null;

    /**
     * Fired whenever the mouse leaves the boundaries of the element associated
     * with this Guacamole.Mouse.
     * 
     * @event
     */
	this.onmouseout = null;

    /**
     * Counter of mouse events to ignore. This decremented by mousemove, and
     * while non-zero, mouse events will have no effect.
     * @private
     */
    var ignore_mouse = 0;

    /**
     * Cumulative scroll delta amount. This value is accumulated through scroll
     * events and results in scroll button clicks if it exceeds a certain
     * threshold.
     *
     * @private
     */
    var scroll_delta = 0;

    function cancelEvent(e) {
        e.stopPropagation();
        if (e.preventDefault) e.preventDefault();
        e.returnValue = false;
    }

    // Block context menu so right-click gets sent properly
    element.addEventListener("contextmenu", function(e) {
        cancelEvent(e);
    }, false);

    element.addEventListener("mousemove", function(e) {

        cancelEvent(e);

        // If ignoring events, decrement counter
        if (ignore_mouse) {
            ignore_mouse--;
            return;
        }

        guac_mouse.currentState.fromClientPosition(element, e.clientX, e.clientY);

        if (guac_mouse.onmousemove)
            guac_mouse.onmousemove(guac_mouse.currentState);

    }, false);

    element.addEventListener("mousedown", function(e) {

        cancelEvent(e);

        // Do not handle if ignoring events
        if (ignore_mouse)
            return;

        switch (e.button) {
            case 0:
                guac_mouse.currentState.left = true;
                break;
            case 1:
                guac_mouse.currentState.middle = true;
                break;
            case 2:
                guac_mouse.currentState.right = true;
                break;
        }

        if (guac_mouse.onmousedown)
            guac_mouse.onmousedown(guac_mouse.currentState);

    }, false);

    element.addEventListener("mouseup", function(e) {

        cancelEvent(e);

        // Do not handle if ignoring events
        if (ignore_mouse)
            return;

        switch (e.button) {
            case 0:
                guac_mouse.currentState.left = false;
                break;
            case 1:
                guac_mouse.currentState.middle = false;
                break;
            case 2:
                guac_mouse.currentState.right = false;
                break;
        }

        if (guac_mouse.onmouseup)
            guac_mouse.onmouseup(guac_mouse.currentState);

    }, false);

    element.addEventListener("mouseout", function(e) {

        // Get parent of the element the mouse pointer is leaving
       	if (!e) e = window.event;

        // Check that mouseout is due to actually LEAVING the element
        var target = e.relatedTarget || e.toElement;
        while (target) {
            if (target === element)
                return;
            target = target.parentNode;
        }

        cancelEvent(e);

        // Release all buttons
        if (guac_mouse.currentState.left
            || guac_mouse.currentState.middle
            || guac_mouse.currentState.right) {

            guac_mouse.currentState.left = false;
            guac_mouse.currentState.middle = false;
            guac_mouse.currentState.right = false;

            if (guac_mouse.onmouseup)
                guac_mouse.onmouseup(guac_mouse.currentState);
        }

        // Fire onmouseout event
        if (guac_mouse.onmouseout)
            guac_mouse.onmouseout();

    }, false);

    // Override selection on mouse event element.
    element.addEventListener("selectstart", function(e) {
        cancelEvent(e);
    }, false);

    // Ignore all pending mouse events when touch events are the apparent source
    function ignorePendingMouseEvents() { ignore_mouse = guac_mouse.touchMouseThreshold; }

    element.addEventListener("touchmove",  ignorePendingMouseEvents, false);
    element.addEventListener("touchstart", ignorePendingMouseEvents, false);
    element.addEventListener("touchend",   ignorePendingMouseEvents, false);

    // Scroll wheel support
    function mousewheel_handler(e) {

        // Determine approximate scroll amount (in pixels)
        var delta = e.deltaY || -e.wheelDeltaY || -e.wheelDelta;

        // If successfully retrieved scroll amount, convert to pixels if not
        // already in pixels
        if (delta) {

            // Convert to pixels if delta was lines
            if (e.deltaMode === 1)
                delta = e.deltaY * guac_mouse.PIXELS_PER_LINE;

            // Convert to pixels if delta was pages
            else if (e.deltaMode === 2)
                delta = e.deltaY * guac_mouse.PIXELS_PER_PAGE;

        }

        // Otherwise, assume legacy mousewheel event and line scrolling
        else
            delta = e.detail * guac_mouse.PIXELS_PER_LINE;
        
        // Update overall delta
        scroll_delta += delta;

        // Up
        if (scroll_delta <= -guac_mouse.scrollThreshold) {

            // Repeatedly click the up button until insufficient delta remains
            do {

                if (guac_mouse.onmousedown) {
                    guac_mouse.currentState.up = true;
                    guac_mouse.onmousedown(guac_mouse.currentState);
                }

                if (guac_mouse.onmouseup) {
                    guac_mouse.currentState.up = false;
                    guac_mouse.onmouseup(guac_mouse.currentState);
                }

                scroll_delta += guac_mouse.scrollThreshold;

            } while (scroll_delta <= -guac_mouse.scrollThreshold);

            // Reset delta
            scroll_delta = 0;

        }

        // Down
        if (scroll_delta >= guac_mouse.scrollThreshold) {

            // Repeatedly click the down button until insufficient delta remains
            do {

                if (guac_mouse.onmousedown) {
                    guac_mouse.currentState.down = true;
                    guac_mouse.onmousedown(guac_mouse.currentState);
                }

                if (guac_mouse.onmouseup) {
                    guac_mouse.currentState.down = false;
                    guac_mouse.onmouseup(guac_mouse.currentState);
                }

                scroll_delta -= guac_mouse.scrollThreshold;

            } while (scroll_delta >= guac_mouse.scrollThreshold);

            // Reset delta
            scroll_delta = 0;

        }

        cancelEvent(e);

    }

    element.addEventListener('DOMMouseScroll', mousewheel_handler, false);
    element.addEventListener('mousewheel',     mousewheel_handler, false);
    element.addEventListener('wheel',          mousewheel_handler, false);

    /**
     * Whether the browser supports CSS3 cursor styling, including hotspot
     * coordinates.
     *
     * @private
     * @type {Boolean}
     */
    var CSS3_CURSOR_SUPPORTED = (function() {

        var div = document.createElement("div");

        // If no cursor property at all, then no support
        if (!("cursor" in div.style))
            return false;

        try {
            // Apply simple 1x1 PNG
            div.style.cursor = "url(data:image/png;base64,"
                             + "iVBORw0KGgoAAAANSUhEUgAAAAEAAAAB"
                             + "AQMAAAAl21bKAAAAA1BMVEX///+nxBvI"
                             + "AAAACklEQVQI12NgAAAAAgAB4iG8MwAA"
                             + "AABJRU5ErkJggg==) 0 0, auto";
        }
        catch (e) {
            return false;
        }

        // Verify cursor property is set to URL with hotspot
        return /\burl\([^()]*\)\s+0\s+0\b/.test(div.style.cursor || "");

    })();

    /**
     * Changes the local mouse cursor to the given canvas, having the given
     * hotspot coordinates. This affects styling of the element backing this
     * Guacamole.Mouse only, and may fail depending on browser support for
     * setting the mouse cursor.
     * 
     * If setting the local cursor is desired, it is up to the implementation
     * to do something else, such as use the software cursor built into
     * Guacamole.Display, if the local cursor cannot be set.
     *
     * @param {HTMLCanvasElement} canvas The cursor image.
     * @param {Number} x The X-coordinate of the cursor hotspot.
     * @param {Number} y The Y-coordinate of the cursor hotspot.
     * @return {Boolean} true if the cursor was successfully set, false if the
     *                   cursor could not be set for any reason.
     */
    this.setCursor = function(canvas, x, y) {

        // Attempt to set via CSS3 cursor styling
        if (CSS3_CURSOR_SUPPORTED) {
            var dataURL = canvas.toDataURL('image/png');
            element.style.cursor = "url(" + dataURL + ") " + x + " " + y + ", auto";
            return true;
        }

        // Otherwise, setting cursor failed
        return false;

    };

};

/**
 * Simple container for properties describing the state of a mouse.
 * 
 * @constructor
 * @param {Number} x The X position of the mouse pointer in pixels.
 * @param {Number} y The Y position of the mouse pointer in pixels.
 * @param {Boolean} left Whether the left mouse button is pressed. 
 * @param {Boolean} middle Whether the middle mouse button is pressed. 
 * @param {Boolean} right Whether the right mouse button is pressed. 
 * @param {Boolean} up Whether the up mouse button is pressed (the fourth
 *                     button, usually part of a scroll wheel). 
 * @param {Boolean} down Whether the down mouse button is pressed (the fifth
 *                       button, usually part of a scroll wheel). 
 */
Guacamole.Mouse.State = function(x, y, left, middle, right, up, down) {

    /**
     * Reference to this Guacamole.Mouse.State.
     * @private
     */
    var guac_state = this;

    /**
     * The current X position of the mouse pointer.
     * @type {Number}
     */
    this.x = x;

    /**
     * The current Y position of the mouse pointer.
     * @type {Number}
     */
    this.y = y;

    /**
     * Whether the left mouse button is currently pressed.
     * @type {Boolean}
     */
    this.left = left;

    /**
     * Whether the middle mouse button is currently pressed.
     * @type {Boolean}
     */
    this.middle = middle;

    /**
     * Whether the right mouse button is currently pressed.
     * @type {Boolean}
     */
    this.right = right;

    /**
     * Whether the up mouse button is currently pressed. This is the fourth
     * mouse button, associated with upward scrolling of the mouse scroll
     * wheel.
     * @type {Boolean}
     */
    this.up = up;

    /**
     * Whether the down mouse button is currently pressed. This is the fifth 
     * mouse button, associated with downward scrolling of the mouse scroll
     * wheel.
     * @type {Boolean}
     */
    this.down = down;

    /**
     * Updates the position represented within this state object by the given
     * element and clientX/clientY coordinates (commonly available within event
     * objects). Position is translated from clientX/clientY (relative to
     * viewport) to element-relative coordinates.
     * 
     * @param {Element} element The element the coordinates should be relative
     *                          to.
     * @param {Number} clientX The X coordinate to translate, viewport-relative.
     * @param {Number} clientY The Y coordinate to translate, viewport-relative.
     */
    this.fromClientPosition = function(element, clientX, clientY) {
    
        guac_state.x = clientX - element.offsetLeft;
        guac_state.y = clientY - element.offsetTop;

        // This is all JUST so we can get the mouse position within the element
        var parent = element.offsetParent;
        while (parent && !(parent === document.body)) {
            guac_state.x -= parent.offsetLeft - parent.scrollLeft;
            guac_state.y -= parent.offsetTop  - parent.scrollTop;

            parent = parent.offsetParent;
        }

        // Element ultimately depends on positioning within document body,
        // take document scroll into account. 
        if (parent) {
            var documentScrollLeft = document.body.scrollLeft || document.documentElement.scrollLeft;
            var documentScrollTop = document.body.scrollTop || document.documentElement.scrollTop;

            guac_state.x -= parent.offsetLeft - documentScrollLeft;
            guac_state.y -= parent.offsetTop  - documentScrollTop;
        }

    };

};

/**
 * Provides cross-browser relative touch event translation for a given element.
 * 
 * Touch events are translated into mouse events as if the touches occurred
 * on a touchpad (drag to push the mouse pointer, tap to click).
 * 
 * @constructor
 * @param {Element} element The Element to use to provide touch events.
 */
Guacamole.Mouse.Touchpad = function(element) {

    /**
     * Reference to this Guacamole.Mouse.Touchpad.
     * @private
     */
    var guac_touchpad = this;

    /**
     * The distance a two-finger touch must move per scrollwheel event, in
     * pixels.
     */
    this.scrollThreshold = 20 * (window.devicePixelRatio || 1);

    /**
     * The maximum number of milliseconds to wait for a touch to end for the
     * gesture to be considered a click.
     */
    this.clickTimingThreshold = 250;

    /**
     * The maximum number of pixels to allow a touch to move for the gesture to
     * be considered a click.
     */
    this.clickMoveThreshold = 10 * (window.devicePixelRatio || 1);

    /**
     * The current mouse state. The properties of this state are updated when
     * mouse events fire. This state object is also passed in as a parameter to
     * the handler of any mouse events.
     * 
     * @type {Guacamole.Mouse.State}
     */
    this.currentState = new Guacamole.Mouse.State(
        0, 0, 
        false, false, false, false, false
    );

    /**
     * Fired whenever a mouse button is effectively pressed. This can happen
     * as part of a "click" gesture initiated by the user by tapping one
     * or more fingers over the touchpad element, as part of a "scroll"
     * gesture initiated by dragging two fingers up or down, etc.
     * 
     * @event
     * @param {Guacamole.Mouse.State} state The current mouse state.
     */
	this.onmousedown = null;

    /**
     * Fired whenever a mouse button is effectively released. This can happen
     * as part of a "click" gesture initiated by the user by tapping one
     * or more fingers over the touchpad element, as part of a "scroll"
     * gesture initiated by dragging two fingers up or down, etc.
     * 
     * @event
     * @param {Guacamole.Mouse.State} state The current mouse state.
     */
	this.onmouseup = null;

    /**
     * Fired whenever the user moves the mouse by dragging their finger over
     * the touchpad element.
     * 
     * @event
     * @param {Guacamole.Mouse.State} state The current mouse state.
     */
	this.onmousemove = null;

    var touch_count = 0;
    var last_touch_x = 0;
    var last_touch_y = 0;
    var last_touch_time = 0;
    var pixels_moved = 0;

    var touch_buttons = {
        1: "left",
        2: "right",
        3: "middle"
    };

    var gesture_in_progress = false;
    var click_release_timeout = null;

    element.addEventListener("touchend", function(e) {
        
        e.preventDefault();
            
        // If we're handling a gesture AND this is the last touch
        if (gesture_in_progress && e.touches.length === 0) {
            
            var time = new Date().getTime();

            // Get corresponding mouse button
            var button = touch_buttons[touch_count];

            // If mouse already down, release anad clear timeout
            if (guac_touchpad.currentState[button]) {

                // Fire button up event
                guac_touchpad.currentState[button] = false;
                if (guac_touchpad.onmouseup)
                    guac_touchpad.onmouseup(guac_touchpad.currentState);

                // Clear timeout, if set
                if (click_release_timeout) {
                    window.clearTimeout(click_release_timeout);
                    click_release_timeout = null;
                }

            }

            // If single tap detected (based on time and distance)
            if (time - last_touch_time <= guac_touchpad.clickTimingThreshold
                    && pixels_moved < guac_touchpad.clickMoveThreshold) {

                // Fire button down event
                guac_touchpad.currentState[button] = true;
                if (guac_touchpad.onmousedown)
                    guac_touchpad.onmousedown(guac_touchpad.currentState);

                // Delay mouse up - mouse up should be canceled if
                // touchstart within timeout.
                click_release_timeout = window.setTimeout(function() {
                    
                    // Fire button up event
                    guac_touchpad.currentState[button] = false;
                    if (guac_touchpad.onmouseup)
                        guac_touchpad.onmouseup(guac_touchpad.currentState);
                    
                    // Gesture now over
                    gesture_in_progress = false;

                }, guac_touchpad.clickTimingThreshold);

            }

            // If we're not waiting to see if this is a click, stop gesture
            if (!click_release_timeout)
                gesture_in_progress = false;

        }

    }, false);

    element.addEventListener("touchstart", function(e) {

        e.preventDefault();

        // Track number of touches, but no more than three
        touch_count = Math.min(e.touches.length, 3);

        // Clear timeout, if set
        if (click_release_timeout) {
            window.clearTimeout(click_release_timeout);
            click_release_timeout = null;
        }

        // Record initial touch location and time for touch movement
        // and tap gestures
        if (!gesture_in_progress) {

            // Stop mouse events while touching
            gesture_in_progress = true;

            // Record touch location and time
            var starting_touch = e.touches[0];
            last_touch_x = starting_touch.clientX;
            last_touch_y = starting_touch.clientY;
            last_touch_time = new Date().getTime();
            pixels_moved = 0;

        }

    }, false);

    element.addEventListener("touchmove", function(e) {

        e.preventDefault();

        // Get change in touch location
        var touch = e.touches[0];
        var delta_x = touch.clientX - last_touch_x;
        var delta_y = touch.clientY - last_touch_y;

        // Track pixels moved
        pixels_moved += Math.abs(delta_x) + Math.abs(delta_y);

        // If only one touch involved, this is mouse move
        if (touch_count === 1) {

            // Calculate average velocity in Manhatten pixels per millisecond
            var velocity = pixels_moved / (new Date().getTime() - last_touch_time);

            // Scale mouse movement relative to velocity
            var scale = 1 + velocity;

            // Update mouse location
            guac_touchpad.currentState.x += delta_x*scale;
            guac_touchpad.currentState.y += delta_y*scale;

            // Prevent mouse from leaving screen

            if (guac_touchpad.currentState.x < 0)
                guac_touchpad.currentState.x = 0;
            else if (guac_touchpad.currentState.x >= element.offsetWidth)
                guac_touchpad.currentState.x = element.offsetWidth - 1;

            if (guac_touchpad.currentState.y < 0)
                guac_touchpad.currentState.y = 0;
            else if (guac_touchpad.currentState.y >= element.offsetHeight)
                guac_touchpad.currentState.y = element.offsetHeight - 1;

            // Fire movement event, if defined
            if (guac_touchpad.onmousemove)
                guac_touchpad.onmousemove(guac_touchpad.currentState);

            // Update touch location
            last_touch_x = touch.clientX;
            last_touch_y = touch.clientY;

        }

        // Interpret two-finger swipe as scrollwheel
        else if (touch_count === 2) {

            // If change in location passes threshold for scroll
            if (Math.abs(delta_y) >= guac_touchpad.scrollThreshold) {

                // Decide button based on Y movement direction
                var button;
                if (delta_y > 0) button = "down";
                else             button = "up";

                // Fire button down event
                guac_touchpad.currentState[button] = true;
                if (guac_touchpad.onmousedown)
                    guac_touchpad.onmousedown(guac_touchpad.currentState);

                // Fire button up event
                guac_touchpad.currentState[button] = false;
                if (guac_touchpad.onmouseup)
                    guac_touchpad.onmouseup(guac_touchpad.currentState);

                // Only update touch location after a scroll has been
                // detected
                last_touch_x = touch.clientX;
                last_touch_y = touch.clientY;

            }

        }

    }, false);

};

/**
 * Provides cross-browser absolute touch event translation for a given element.
 *
 * Touch events are translated into mouse events as if the touches occurred
 * on a touchscreen (tapping anywhere on the screen clicks at that point,
 * long-press to right-click).
 *
 * @constructor
 * @param {Element} element The Element to use to provide touch events.
 */
Guacamole.Mouse.Touchscreen = function(element) {

    /**
     * Reference to this Guacamole.Mouse.Touchscreen.
     * @private
     */
    var guac_touchscreen = this;

    /**
     * Whether a gesture is known to be in progress. If false, touch events
     * will be ignored.
     *
     * @private
     */
    var gesture_in_progress = false;

    /**
     * The start X location of a gesture.
     * @private
     */
    var gesture_start_x = null;

    /**
     * The start Y location of a gesture.
     * @private
     */
    var gesture_start_y = null;

    /**
     * The timeout associated with the delayed, cancellable click release.
     *
     * @private
     */
    var click_release_timeout = null;

    /**
     * The timeout associated with long-press for right click.
     *
     * @private
     */
    var long_press_timeout = null;

    /**
     * The distance a two-finger touch must move per scrollwheel event, in
     * pixels.
     */
    this.scrollThreshold = 20 * (window.devicePixelRatio || 1);

    /**
     * The maximum number of milliseconds to wait for a touch to end for the
     * gesture to be considered a click.
     */
    this.clickTimingThreshold = 250;

    /**
     * The maximum number of pixels to allow a touch to move for the gesture to
     * be considered a click.
     */
    this.clickMoveThreshold = 16 * (window.devicePixelRatio || 1);

    /**
     * The amount of time a press must be held for long press to be
     * detected.
     */
    this.longPressThreshold = 500;

    /**
     * The current mouse state. The properties of this state are updated when
     * mouse events fire. This state object is also passed in as a parameter to
     * the handler of any mouse events.
     *
     * @type {Guacamole.Mouse.State}
     */
    this.currentState = new Guacamole.Mouse.State(
        0, 0,
        false, false, false, false, false
    );

    /**
     * Fired whenever a mouse button is effectively pressed. This can happen
     * as part of a "mousedown" gesture initiated by the user by pressing one
     * finger over the touchscreen element, as part of a "scroll" gesture
     * initiated by dragging two fingers up or down, etc.
     *
     * @event
     * @param {Guacamole.Mouse.State} state The current mouse state.
     */
	this.onmousedown = null;

    /**
     * Fired whenever a mouse button is effectively released. This can happen
     * as part of a "mouseup" gesture initiated by the user by removing the
     * finger pressed against the touchscreen element, or as part of a "scroll"
     * gesture initiated by dragging two fingers up or down, etc.
     *
     * @event
     * @param {Guacamole.Mouse.State} state The current mouse state.
     */
	this.onmouseup = null;

    /**
     * Fired whenever the user moves the mouse by dragging their finger over
     * the touchscreen element. Note that unlike Guacamole.Mouse.Touchpad,
     * dragging a finger over the touchscreen element will always cause
     * the mouse button to be effectively down, as if clicking-and-dragging.
     *
     * @event
     * @param {Guacamole.Mouse.State} state The current mouse state.
     */
	this.onmousemove = null;

    /**
     * Presses the given mouse button, if it isn't already pressed. Valid
     * button values are "left", "middle", "right", "up", and "down".
     *
     * @private
     * @param {String} button The mouse button to press.
     */
    function press_button(button) {
        if (!guac_touchscreen.currentState[button]) {
            guac_touchscreen.currentState[button] = true;
            if (guac_touchscreen.onmousedown)
                guac_touchscreen.onmousedown(guac_touchscreen.currentState);
        }
    }

    /**
     * Releases the given mouse button, if it isn't already released. Valid
     * button values are "left", "middle", "right", "up", and "down".
     *
     * @private
     * @param {String} button The mouse button to release.
     */
    function release_button(button) {
        if (guac_touchscreen.currentState[button]) {
            guac_touchscreen.currentState[button] = false;
            if (guac_touchscreen.onmouseup)
                guac_touchscreen.onmouseup(guac_touchscreen.currentState);
        }
    }

    /**
     * Clicks (presses and releases) the given mouse button. Valid button
     * values are "left", "middle", "right", "up", and "down".
     *
     * @private
     * @param {String} button The mouse button to click.
     */
    function click_button(button) {
        press_button(button);
        release_button(button);
    }

    /**
     * Moves the mouse to the given coordinates. These coordinates must be
     * relative to the browser window, as they will be translated based on
     * the touch event target's location within the browser window.
     *
     * @private
     * @param {Number} x The X coordinate of the mouse pointer.
     * @param {Number} y The Y coordinate of the mouse pointer.
     */
    function move_mouse(x, y) {
        guac_touchscreen.currentState.fromClientPosition(element, x, y);
        if (guac_touchscreen.onmousemove)
            guac_touchscreen.onmousemove(guac_touchscreen.currentState);
    }

    /**
     * Returns whether the given touch event exceeds the movement threshold for
     * clicking, based on where the touch gesture began.
     *
     * @private
     * @param {TouchEvent} e The touch event to check.
     * @return {Boolean} true if the movement threshold is exceeded, false
     *                   otherwise.
     */
    function finger_moved(e) {
        var touch = e.touches[0] || e.changedTouches[0];
        var delta_x = touch.clientX - gesture_start_x;
        var delta_y = touch.clientY - gesture_start_y;
        return Math.sqrt(delta_x*delta_x + delta_y*delta_y) >= guac_touchscreen.clickMoveThreshold;
    }

    /**
     * Begins a new gesture at the location of the first touch in the given
     * touch event.
     * 
     * @private
     * @param {TouchEvent} e The touch event beginning this new gesture.
     */
    function begin_gesture(e) {
        var touch = e.touches[0];
        gesture_in_progress = true;
        gesture_start_x = touch.clientX;
        gesture_start_y = touch.clientY;
    }

    /**
     * End the current gesture entirely. Wait for all touches to be done before
     * resuming gesture detection.
     * 
     * @private
     */
    function end_gesture() {
        window.clearTimeout(click_release_timeout);
        window.clearTimeout(long_press_timeout);
        gesture_in_progress = false;
    }

    element.addEventListener("touchend", function(e) {

        // Do not handle if no gesture
        if (!gesture_in_progress)
            return;

        // Ignore if more than one touch
        if (e.touches.length !== 0 || e.changedTouches.length !== 1) {
            end_gesture();
            return;
        }

        // Long-press, if any, is over
        window.clearTimeout(long_press_timeout);

        // Always release mouse button if pressed
        release_button("left");

        // If finger hasn't moved enough to cancel the click
        if (!finger_moved(e)) {

            e.preventDefault();

            // If not yet pressed, press and start delay release
            if (!guac_touchscreen.currentState.left) {

                var touch = e.changedTouches[0];
                move_mouse(touch.clientX, touch.clientY);
                press_button("left");

                // Release button after a delay, if not canceled
                click_release_timeout = window.setTimeout(function() {
                    release_button("left");
                    end_gesture();
                }, guac_touchscreen.clickTimingThreshold);

            }

        } // end if finger not moved

    }, false);

    element.addEventListener("touchstart", function(e) {

        // Ignore if more than one touch
        if (e.touches.length !== 1) {
            end_gesture();
            return;
        }

        e.preventDefault();

        // New touch begins a new gesture
        begin_gesture(e);

        // Keep button pressed if tap after left click
        window.clearTimeout(click_release_timeout);

        // Click right button if this turns into a long-press
        long_press_timeout = window.setTimeout(function() {
            var touch = e.touches[0];
            move_mouse(touch.clientX, touch.clientY);
            click_button("right");
            end_gesture();
        }, guac_touchscreen.longPressThreshold);

    }, false);

    element.addEventListener("touchmove", function(e) {

        // Do not handle if no gesture
        if (!gesture_in_progress)
            return;

        // Cancel long press if finger moved
        if (finger_moved(e))
            window.clearTimeout(long_press_timeout);

        // Ignore if more than one touch
        if (e.touches.length !== 1) {
            end_gesture();
            return;
        }

        // Update mouse position if dragging
        if (guac_touchscreen.currentState.left) {

            e.preventDefault();

            // Update state
            var touch = e.touches[0];
            move_mouse(touch.clientX, touch.clientY);

        }

    }, false);

};
