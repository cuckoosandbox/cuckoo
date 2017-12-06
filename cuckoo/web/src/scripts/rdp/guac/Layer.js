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
 * Abstract ordered drawing surface. Each Layer contains a canvas element and
 * provides simple drawing instructions for drawing to that canvas element,
 * however unlike the canvas element itself, drawing operations on a Layer are
 * guaranteed to run in order, even if such an operation must wait for an image
 * to load before completing.
 * 
 * @constructor
 * 
 * @param {Number} width The width of the Layer, in pixels. The canvas element
 *                       backing this Layer will be given this width.
 *                       
 * @param {Number} height The height of the Layer, in pixels. The canvas element
 *                        backing this Layer will be given this height.
 */
Guacamole.Layer = function(width, height) {

    /**
     * Reference to this Layer.
     * @private
     */
    var layer = this;

    /**
     * The number of pixels the width or height of a layer must change before
     * the underlying canvas is resized. The underlying canvas will be kept at
     * dimensions which are integer multiples of this factor.
     *
     * @private
     * @constant
     * @type Number
     */
    var CANVAS_SIZE_FACTOR = 64;

    /**
     * The canvas element backing this Layer.
     * @private
     */
    var canvas = document.createElement("canvas");

    /**
     * The 2D display context of the canvas element backing this Layer.
     * @private
     */
    var context = canvas.getContext("2d");
    context.save();

    /**
     * Whether the layer has not yet been drawn to. Once any draw operation
     * which affects the underlying canvas is invoked, this flag will be set to
     * false.
     *
     * @private
     * @type Boolean
     */
    var empty = true;

    /**
     * Whether a new path should be started with the next path drawing
     * operations.
     * @private
     */
    var pathClosed = true;

    /**
     * The number of states on the state stack.
     * 
     * Note that there will ALWAYS be one element on the stack, but that
     * element is not exposed. It is only used to reset the layer to its
     * initial state.
     * 
     * @private
     */
    var stackSize = 0;

    /**
     * Map of all Guacamole channel masks to HTML5 canvas composite operation
     * names. Not all channel mask combinations are currently implemented.
     * @private
     */
    var compositeOperation = {
     /* 0x0 NOT IMPLEMENTED */
        0x1: "destination-in",
        0x2: "destination-out",
     /* 0x3 NOT IMPLEMENTED */
        0x4: "source-in",
     /* 0x5 NOT IMPLEMENTED */
        0x6: "source-atop",
     /* 0x7 NOT IMPLEMENTED */
        0x8: "source-out",
        0x9: "destination-atop",
        0xA: "xor",
        0xB: "destination-over",
        0xC: "copy",
     /* 0xD NOT IMPLEMENTED */
        0xE: "source-over",
        0xF: "lighter"
    };

    /**
     * Resizes the canvas element backing this Layer. This function should only
     * be used internally.
     * 
     * @private
     * @param {Number} [newWidth=0]
     *     The new width to assign to this Layer.
     *
     * @param {Number} [newHeight=0]
     *     The new height to assign to this Layer.
     */
    var resize = function resize(newWidth, newHeight) {

        // Default size to zero
        newWidth = newWidth || 0;
        newHeight = newHeight || 0;

        // Calculate new dimensions of internal canvas
        var canvasWidth  = Math.ceil(newWidth  / CANVAS_SIZE_FACTOR) * CANVAS_SIZE_FACTOR;
        var canvasHeight = Math.ceil(newHeight / CANVAS_SIZE_FACTOR) * CANVAS_SIZE_FACTOR;

        // Resize only if canvas dimensions are actually changing
        if (canvas.width !== canvasWidth || canvas.height !== canvasHeight) {

            // Copy old data only if relevant and non-empty
            var oldData = null;
            if (!empty && canvas.width !== 0 && canvas.height !== 0) {

                // Create canvas and context for holding old data
                oldData = document.createElement("canvas");
                oldData.width = Math.min(layer.width, newWidth);
                oldData.height = Math.min(layer.height, newHeight);

                var oldDataContext = oldData.getContext("2d");

                // Copy image data from current
                oldDataContext.drawImage(canvas,
                        0, 0, oldData.width, oldData.height,
                        0, 0, oldData.width, oldData.height);

            }

            // Preserve composite operation
            var oldCompositeOperation = context.globalCompositeOperation;

            // Resize canvas
            canvas.width = canvasWidth;
            canvas.height = canvasHeight;

            // Redraw old data, if any
            if (oldData)
                context.drawImage(oldData,
                    0, 0, oldData.width, oldData.height,
                    0, 0, oldData.width, oldData.height);

            // Restore composite operation
            context.globalCompositeOperation = oldCompositeOperation;

            // Acknowledge reset of stack (happens on resize of canvas)
            stackSize = 0;
            context.save();

        }

        // If the canvas size is not changing, manually force state reset
        else
            layer.reset();

        // Assign new layer dimensions
        layer.width = newWidth;
        layer.height = newHeight;

    };

    /**
     * Given the X and Y coordinates of the upper-left corner of a rectangle
     * and the rectangle's width and height, resize the backing canvas element
     * as necessary to ensure that the rectangle fits within the canvas
     * element's coordinate space. This function will only make the canvas
     * larger. If the rectangle already fits within the canvas element's
     * coordinate space, the canvas is left unchanged.
     * 
     * @private
     * @param {Number} x The X coordinate of the upper-left corner of the
     *                   rectangle to fit.
     * @param {Number} y The Y coordinate of the upper-left corner of the
     *                   rectangle to fit.
     * @param {Number} w The width of the the rectangle to fit.
     * @param {Number} h The height of the the rectangle to fit.
     */
    function fitRect(x, y, w, h) {
        
        // Calculate bounds
        var opBoundX = w + x;
        var opBoundY = h + y;
        
        // Determine max width
        var resizeWidth;
        if (opBoundX > layer.width)
            resizeWidth = opBoundX;
        else
            resizeWidth = layer.width;

        // Determine max height
        var resizeHeight;
        if (opBoundY > layer.height)
            resizeHeight = opBoundY;
        else
            resizeHeight = layer.height;

        // Resize if necessary
        layer.resize(resizeWidth, resizeHeight);

    }

    /**
     * Set to true if this Layer should resize itself to accomodate the
     * dimensions of any drawing operation, and false (the default) otherwise.
     * 
     * Note that setting this property takes effect immediately, and thus may
     * take effect on operations that were started in the past but have not
     * yet completed. If you wish the setting of this flag to only modify
     * future operations, you will need to make the setting of this flag an
     * operation with sync().
     * 
     * @example
     * // Set autosize to true for all future operations
     * layer.sync(function() {
     *     layer.autosize = true;
     * });
     * 
     * @type {Boolean}
     * @default false
     */
    this.autosize = false;

    /**
     * The current width of this layer.
     * @type {Number}
     */
    this.width = width;

    /**
     * The current height of this layer.
     * @type {Number}
     */
    this.height = height;

    /**
     * Returns the canvas element backing this Layer. Note that the dimensions
     * of the canvas may not exactly match those of the Layer, as resizing a
     * canvas while maintaining its state is an expensive operation.
     *
     * @returns {HTMLCanvasElement}
     *     The canvas element backing this Layer.
     */
    this.getCanvas = function getCanvas() {
        return canvas;
    };

    /**
     * Returns a new canvas element containing the same image as this Layer.
     * Unlike getCanvas(), the canvas element returned is guaranteed to have
     * the exact same dimensions as the Layer.
     *
     * @returns {HTMLCanvasElement}
     *     A new canvas element containing a copy of the image content this
     *     Layer.
     */
    this.toCanvas = function toCanvas() {

        // Create new canvas having same dimensions
        var canvas = document.createElement('canvas');
        canvas.width = layer.width;
        canvas.height = layer.height;

        // Copy image contents to new canvas
        var context = canvas.getContext('2d');
        context.drawImage(layer.getCanvas(), 0, 0);

        return canvas;

    };

    /**
     * Changes the size of this Layer to the given width and height. Resizing
     * is only attempted if the new size provided is actually different from
     * the current size.
     * 
     * @param {Number} newWidth The new width to assign to this Layer.
     * @param {Number} newHeight The new height to assign to this Layer.
     */
    this.resize = function(newWidth, newHeight) {
        if (newWidth !== layer.width || newHeight !== layer.height)
            resize(newWidth, newHeight);
    };

    /**
     * Draws the specified image at the given coordinates. The image specified
     * must already be loaded.
     * 
     * @param {Number} x The destination X coordinate.
     * @param {Number} y The destination Y coordinate.
     * @param {Image} image The image to draw. Note that this is an Image
     *                      object - not a URL.
     */
    this.drawImage = function(x, y, image) {
        if (layer.autosize) fitRect(x, y, image.width, image.height);
        context.drawImage(image, x, y);
        empty = false;
    };

    /**
     * Transfer a rectangle of image data from one Layer to this Layer using the
     * specified transfer function.
     * 
     * @param {Guacamole.Layer} srcLayer The Layer to copy image data from.
     * @param {Number} srcx The X coordinate of the upper-left corner of the
     *                      rectangle within the source Layer's coordinate
     *                      space to copy data from.
     * @param {Number} srcy The Y coordinate of the upper-left corner of the
     *                      rectangle within the source Layer's coordinate
     *                      space to copy data from.
     * @param {Number} srcw The width of the rectangle within the source Layer's
     *                      coordinate space to copy data from.
     * @param {Number} srch The height of the rectangle within the source
     *                      Layer's coordinate space to copy data from.
     * @param {Number} x The destination X coordinate.
     * @param {Number} y The destination Y coordinate.
     * @param {Function} transferFunction The transfer function to use to
     *                                    transfer data from source to
     *                                    destination.
     */
    this.transfer = function(srcLayer, srcx, srcy, srcw, srch, x, y, transferFunction) {

        var srcCanvas = srcLayer.getCanvas();

        // If entire rectangle outside source canvas, stop
        if (srcx >= srcCanvas.width || srcy >= srcCanvas.height) return;

        // Otherwise, clip rectangle to area
        if (srcx + srcw > srcCanvas.width)
            srcw = srcCanvas.width - srcx;

        if (srcy + srch > srcCanvas.height)
            srch = srcCanvas.height - srcy;

        // Stop if nothing to draw.
        if (srcw === 0 || srch === 0) return;

        if (layer.autosize) fitRect(x, y, srcw, srch);

        // Get image data from src and dst
        var src = srcLayer.getCanvas().getContext("2d").getImageData(srcx, srcy, srcw, srch);
        var dst = context.getImageData(x , y, srcw, srch);

        // Apply transfer for each pixel
        for (var i=0; i<srcw*srch*4; i+=4) {

            // Get source pixel environment
            var src_pixel = new Guacamole.Layer.Pixel(
                src.data[i],
                src.data[i+1],
                src.data[i+2],
                src.data[i+3]
            );
                
            // Get destination pixel environment
            var dst_pixel = new Guacamole.Layer.Pixel(
                dst.data[i],
                dst.data[i+1],
                dst.data[i+2],
                dst.data[i+3]
            );

            // Apply transfer function
            transferFunction(src_pixel, dst_pixel);

            // Save pixel data
            dst.data[i  ] = dst_pixel.red;
            dst.data[i+1] = dst_pixel.green;
            dst.data[i+2] = dst_pixel.blue;
            dst.data[i+3] = dst_pixel.alpha;

        }

        // Draw image data
        context.putImageData(dst, x, y);
        empty = false;

    };

    /**
     * Put a rectangle of image data from one Layer to this Layer directly
     * without performing any alpha blending. Simply copy the data.
     * 
     * @param {Guacamole.Layer} srcLayer The Layer to copy image data from.
     * @param {Number} srcx The X coordinate of the upper-left corner of the
     *                      rectangle within the source Layer's coordinate
     *                      space to copy data from.
     * @param {Number} srcy The Y coordinate of the upper-left corner of the
     *                      rectangle within the source Layer's coordinate
     *                      space to copy data from.
     * @param {Number} srcw The width of the rectangle within the source Layer's
     *                      coordinate space to copy data from.
     * @param {Number} srch The height of the rectangle within the source
     *                      Layer's coordinate space to copy data from.
     * @param {Number} x The destination X coordinate.
     * @param {Number} y The destination Y coordinate.
     */
    this.put = function(srcLayer, srcx, srcy, srcw, srch, x, y) {

        var srcCanvas = srcLayer.getCanvas();

        // If entire rectangle outside source canvas, stop
        if (srcx >= srcCanvas.width || srcy >= srcCanvas.height) return;

        // Otherwise, clip rectangle to area
        if (srcx + srcw > srcCanvas.width)
            srcw = srcCanvas.width - srcx;

        if (srcy + srch > srcCanvas.height)
            srch = srcCanvas.height - srcy;

        // Stop if nothing to draw.
        if (srcw === 0 || srch === 0) return;

        if (layer.autosize) fitRect(x, y, srcw, srch);

        // Get image data from src and dst
        var src = srcLayer.getCanvas().getContext("2d").getImageData(srcx, srcy, srcw, srch);
        context.putImageData(src, x, y);
        empty = false;

    };

    /**
     * Copy a rectangle of image data from one Layer to this Layer. This
     * operation will copy exactly the image data that will be drawn once all
     * operations of the source Layer that were pending at the time this
     * function was called are complete. This operation will not alter the
     * size of the source Layer even if its autosize property is set to true.
     * 
     * @param {Guacamole.Layer} srcLayer The Layer to copy image data from.
     * @param {Number} srcx The X coordinate of the upper-left corner of the
     *                      rectangle within the source Layer's coordinate
     *                      space to copy data from.
     * @param {Number} srcy The Y coordinate of the upper-left corner of the
     *                      rectangle within the source Layer's coordinate
     *                      space to copy data from.
     * @param {Number} srcw The width of the rectangle within the source Layer's
     *                      coordinate space to copy data from.
     * @param {Number} srch The height of the rectangle within the source
     *                      Layer's coordinate space to copy data from.
     * @param {Number} x The destination X coordinate.
     * @param {Number} y The destination Y coordinate.
     */
    this.copy = function(srcLayer, srcx, srcy, srcw, srch, x, y) {

        var srcCanvas = srcLayer.getCanvas();

        // If entire rectangle outside source canvas, stop
        if (srcx >= srcCanvas.width || srcy >= srcCanvas.height) return;

        // Otherwise, clip rectangle to area
        if (srcx + srcw > srcCanvas.width)
            srcw = srcCanvas.width - srcx;

        if (srcy + srch > srcCanvas.height)
            srch = srcCanvas.height - srcy;

        // Stop if nothing to draw.
        if (srcw === 0 || srch === 0) return;

        if (layer.autosize) fitRect(x, y, srcw, srch);
        context.drawImage(srcCanvas, srcx, srcy, srcw, srch, x, y, srcw, srch);
        empty = false;

    };

    /**
     * Starts a new path at the specified point.
     * 
     * @param {Number} x The X coordinate of the point to draw.
     * @param {Number} y The Y coordinate of the point to draw.
     */
    this.moveTo = function(x, y) {
        
        // Start a new path if current path is closed
        if (pathClosed) {
            context.beginPath();
            pathClosed = false;
        }
        
        if (layer.autosize) fitRect(x, y, 0, 0);
        context.moveTo(x, y);

    };

    /**
     * Add the specified line to the current path.
     * 
     * @param {Number} x The X coordinate of the endpoint of the line to draw.
     * @param {Number} y The Y coordinate of the endpoint of the line to draw.
     */
    this.lineTo = function(x, y) {
        
        // Start a new path if current path is closed
        if (pathClosed) {
            context.beginPath();
            pathClosed = false;
        }
        
        if (layer.autosize) fitRect(x, y, 0, 0);
        context.lineTo(x, y);
        
    };

    /**
     * Add the specified arc to the current path.
     * 
     * @param {Number} x The X coordinate of the center of the circle which
     *                   will contain the arc.
     * @param {Number} y The Y coordinate of the center of the circle which
     *                   will contain the arc.
     * @param {Number} radius The radius of the circle.
     * @param {Number} startAngle The starting angle of the arc, in radians.
     * @param {Number} endAngle The ending angle of the arc, in radians.
     * @param {Boolean} negative Whether the arc should be drawn in order of
     *                           decreasing angle.
     */
    this.arc = function(x, y, radius, startAngle, endAngle, negative) {
        
        // Start a new path if current path is closed
        if (pathClosed) {
            context.beginPath();
            pathClosed = false;
        }
        
        if (layer.autosize) fitRect(x, y, 0, 0);
        context.arc(x, y, radius, startAngle, endAngle, negative);
        
    };

    /**
     * Starts a new path at the specified point.
     * 
     * @param {Number} cp1x The X coordinate of the first control point.
     * @param {Number} cp1y The Y coordinate of the first control point.
     * @param {Number} cp2x The X coordinate of the second control point.
     * @param {Number} cp2y The Y coordinate of the second control point.
     * @param {Number} x The X coordinate of the endpoint of the curve.
     * @param {Number} y The Y coordinate of the endpoint of the curve.
     */
    this.curveTo = function(cp1x, cp1y, cp2x, cp2y, x, y) {
        
        // Start a new path if current path is closed
        if (pathClosed) {
            context.beginPath();
            pathClosed = false;
        }
        
        if (layer.autosize) fitRect(x, y, 0, 0);
        context.bezierCurveTo(cp1x, cp1y, cp2x, cp2y, x, y);
        
    };

    /**
     * Closes the current path by connecting the end point with the start
     * point (if any) with a straight line.
     */
    this.close = function() {
        context.closePath();
        pathClosed = true;
    };

    /**
     * Add the specified rectangle to the current path.
     * 
     * @param {Number} x The X coordinate of the upper-left corner of the
     *                   rectangle to draw.
     * @param {Number} y The Y coordinate of the upper-left corner of the
     *                   rectangle to draw.
     * @param {Number} w The width of the rectangle to draw.
     * @param {Number} h The height of the rectangle to draw.
     */
    this.rect = function(x, y, w, h) {
            
        // Start a new path if current path is closed
        if (pathClosed) {
            context.beginPath();
            pathClosed = false;
        }
        
        if (layer.autosize) fitRect(x, y, w, h);
        context.rect(x, y, w, h);
        
    };

    /**
     * Clip all future drawing operations by the current path. The current path
     * is implicitly closed. The current path can continue to be reused
     * for other operations (such as fillColor()) but a new path will be started
     * once a path drawing operation (path() or rect()) is used.
     */
    this.clip = function() {

        // Set new clipping region
        context.clip();

        // Path now implicitly closed
        pathClosed = true;

    };

    /**
     * Stroke the current path with the specified color. The current path
     * is implicitly closed. The current path can continue to be reused
     * for other operations (such as clip()) but a new path will be started
     * once a path drawing operation (path() or rect()) is used.
     * 
     * @param {String} cap The line cap style. Can be "round", "square",
     *                     or "butt".
     * @param {String} join The line join style. Can be "round", "bevel",
     *                      or "miter".
     * @param {Number} thickness The line thickness in pixels.
     * @param {Number} r The red component of the color to fill.
     * @param {Number} g The green component of the color to fill.
     * @param {Number} b The blue component of the color to fill.
     * @param {Number} a The alpha component of the color to fill.
     */
    this.strokeColor = function(cap, join, thickness, r, g, b, a) {

        // Stroke with color
        context.lineCap = cap;
        context.lineJoin = join;
        context.lineWidth = thickness;
        context.strokeStyle = "rgba(" + r + "," + g + "," + b + "," + a/255.0 + ")";
        context.stroke();
        empty = false;

        // Path now implicitly closed
        pathClosed = true;

    };

    /**
     * Fills the current path with the specified color. The current path
     * is implicitly closed. The current path can continue to be reused
     * for other operations (such as clip()) but a new path will be started
     * once a path drawing operation (path() or rect()) is used.
     * 
     * @param {Number} r The red component of the color to fill.
     * @param {Number} g The green component of the color to fill.
     * @param {Number} b The blue component of the color to fill.
     * @param {Number} a The alpha component of the color to fill.
     */
    this.fillColor = function(r, g, b, a) {

        // Fill with color
        context.fillStyle = "rgba(" + r + "," + g + "," + b + "," + a/255.0 + ")";
        context.fill();
        empty = false;

        // Path now implicitly closed
        pathClosed = true;

    };

    /**
     * Stroke the current path with the image within the specified layer. The
     * image data will be tiled infinitely within the stroke. The current path
     * is implicitly closed. The current path can continue to be reused
     * for other operations (such as clip()) but a new path will be started
     * once a path drawing operation (path() or rect()) is used.
     * 
     * @param {String} cap The line cap style. Can be "round", "square",
     *                     or "butt".
     * @param {String} join The line join style. Can be "round", "bevel",
     *                      or "miter".
     * @param {Number} thickness The line thickness in pixels.
     * @param {Guacamole.Layer} srcLayer The layer to use as a repeating pattern
     *                                   within the stroke.
     */
    this.strokeLayer = function(cap, join, thickness, srcLayer) {

        // Stroke with image data
        context.lineCap = cap;
        context.lineJoin = join;
        context.lineWidth = thickness;
        context.strokeStyle = context.createPattern(
            srcLayer.getCanvas(),
            "repeat"
        );
        context.stroke();
        empty = false;

        // Path now implicitly closed
        pathClosed = true;

    };

    /**
     * Fills the current path with the image within the specified layer. The
     * image data will be tiled infinitely within the stroke. The current path
     * is implicitly closed. The current path can continue to be reused
     * for other operations (such as clip()) but a new path will be started
     * once a path drawing operation (path() or rect()) is used.
     * 
     * @param {Guacamole.Layer} srcLayer The layer to use as a repeating pattern
     *                                   within the fill.
     */
    this.fillLayer = function(srcLayer) {

        // Fill with image data 
        context.fillStyle = context.createPattern(
            srcLayer.getCanvas(),
            "repeat"
        );
        context.fill();
        empty = false;

        // Path now implicitly closed
        pathClosed = true;

    };

    /**
     * Push current layer state onto stack.
     */
    this.push = function() {

        // Save current state onto stack
        context.save();
        stackSize++;

    };

    /**
     * Pop layer state off stack.
     */
    this.pop = function() {

        // Restore current state from stack
        if (stackSize > 0) {
            context.restore();
            stackSize--;
        }

    };

    /**
     * Reset the layer, clearing the stack, the current path, and any transform
     * matrix.
     */
    this.reset = function() {

        // Clear stack
        while (stackSize > 0) {
            context.restore();
            stackSize--;
        }

        // Restore to initial state
        context.restore();
        context.save();

        // Clear path
        context.beginPath();
        pathClosed = false;

    };

    /**
     * Sets the given affine transform (defined with six values from the
     * transform's matrix).
     * 
     * @param {Number} a The first value in the affine transform's matrix.
     * @param {Number} b The second value in the affine transform's matrix.
     * @param {Number} c The third value in the affine transform's matrix.
     * @param {Number} d The fourth value in the affine transform's matrix.
     * @param {Number} e The fifth value in the affine transform's matrix.
     * @param {Number} f The sixth value in the affine transform's matrix.
     */
    this.setTransform = function(a, b, c, d, e, f) {
        context.setTransform(
            a, b, c,
            d, e, f
          /*0, 0, 1*/
        );
    };

    /**
     * Applies the given affine transform (defined with six values from the
     * transform's matrix).
     * 
     * @param {Number} a The first value in the affine transform's matrix.
     * @param {Number} b The second value in the affine transform's matrix.
     * @param {Number} c The third value in the affine transform's matrix.
     * @param {Number} d The fourth value in the affine transform's matrix.
     * @param {Number} e The fifth value in the affine transform's matrix.
     * @param {Number} f The sixth value in the affine transform's matrix.
     */
    this.transform = function(a, b, c, d, e, f) {
        context.transform(
            a, b, c,
            d, e, f
          /*0, 0, 1*/
        );
    };

    /**
     * Sets the channel mask for future operations on this Layer.
     * 
     * The channel mask is a Guacamole-specific compositing operation identifier
     * with a single bit representing each of four channels (in order): source
     * image where destination transparent, source where destination opaque,
     * destination where source transparent, and destination where source
     * opaque.
     * 
     * @param {Number} mask The channel mask for future operations on this
     *                      Layer.
     */
    this.setChannelMask = function(mask) {
        context.globalCompositeOperation = compositeOperation[mask];
    };

    /**
     * Sets the miter limit for stroke operations using the miter join. This
     * limit is the maximum ratio of the size of the miter join to the stroke
     * width. If this ratio is exceeded, the miter will not be drawn for that
     * joint of the path.
     * 
     * @param {Number} limit The miter limit for stroke operations using the
     *                       miter join.
     */
    this.setMiterLimit = function(limit) {
        context.miterLimit = limit;
    };

    // Initialize canvas dimensions
    resize(width, height);

    // Explicitly render canvas below other elements in the layer (such as
    // child layers). Chrome and others may fail to render layers properly
    // without this.
    canvas.style.zIndex = -1;

};

/**
 * Channel mask for the composite operation "rout".
 */
Guacamole.Layer.ROUT  = 0x2;

/**
 * Channel mask for the composite operation "atop".
 */
Guacamole.Layer.ATOP  = 0x6;

/**
 * Channel mask for the composite operation "xor".
 */
Guacamole.Layer.XOR   = 0xA;

/**
 * Channel mask for the composite operation "rover".
 */
Guacamole.Layer.ROVER = 0xB;

/**
 * Channel mask for the composite operation "over".
 */
Guacamole.Layer.OVER  = 0xE;

/**
 * Channel mask for the composite operation "plus".
 */
Guacamole.Layer.PLUS  = 0xF;

/**
 * Channel mask for the composite operation "rin".
 * Beware that WebKit-based browsers may leave the contents of the destionation
 * layer where the source layer is transparent, despite the definition of this
 * operation.
 */
Guacamole.Layer.RIN   = 0x1;

/**
 * Channel mask for the composite operation "in".
 * Beware that WebKit-based browsers may leave the contents of the destionation
 * layer where the source layer is transparent, despite the definition of this
 * operation.
 */
Guacamole.Layer.IN    = 0x4;

/**
 * Channel mask for the composite operation "out".
 * Beware that WebKit-based browsers may leave the contents of the destionation
 * layer where the source layer is transparent, despite the definition of this
 * operation.
 */
Guacamole.Layer.OUT   = 0x8;

/**
 * Channel mask for the composite operation "ratop".
 * Beware that WebKit-based browsers may leave the contents of the destionation
 * layer where the source layer is transparent, despite the definition of this
 * operation.
 */
Guacamole.Layer.RATOP = 0x9;

/**
 * Channel mask for the composite operation "src".
 * Beware that WebKit-based browsers may leave the contents of the destionation
 * layer where the source layer is transparent, despite the definition of this
 * operation.
 */
Guacamole.Layer.SRC   = 0xC;

/**
 * Represents a single pixel of image data. All components have a minimum value
 * of 0 and a maximum value of 255.
 * 
 * @constructor
 * 
 * @param {Number} r The red component of this pixel.
 * @param {Number} g The green component of this pixel.
 * @param {Number} b The blue component of this pixel.
 * @param {Number} a The alpha component of this pixel.
 */
Guacamole.Layer.Pixel = function(r, g, b, a) {

    /**
     * The red component of this pixel, where 0 is the minimum value,
     * and 255 is the maximum.
     */
    this.red   = r;

    /**
     * The green component of this pixel, where 0 is the minimum value,
     * and 255 is the maximum.
     */
    this.green = g;

    /**
     * The blue component of this pixel, where 0 is the minimum value,
     * and 255 is the maximum.
     */
    this.blue  = b;

    /**
     * The alpha component of this pixel, where 0 is the minimum value,
     * and 255 is the maximum.
     */
    this.alpha = a;

};
