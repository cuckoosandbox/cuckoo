"use strict";

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

/*
 * Copyright (C) 2010-2013 Claudio Guarnieri.
 * Copyright (C) 2014-2016 Cuckoo Foundation.
 * This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
 * See the file 'docs/LICENSE' for copying permission.
 *
 */

/**
 * An abstract HTML widget for file uploads.
 *
 * Supports:
 *   - Multiple files
 *   - Drag & Drop OR file dialog
 *   - Progress bar
 *   - Minimum size on screen: 300x230
 *
 *   Required parameter `target` takes a CSS selector inside which
 *   the necessary HTML is spawned. Multiple of these widgets can exist on
 *   one page due to OOP.
 */
var DndUpload = function () {
    function DndUpload(target, endpoint, success_callback) {
        _classCallCheck(this, DndUpload);

        this.endpoint = endpoint;
        this._success_callback = success_callback;
        this._selectors = {
            "uid": "dndupload_" + DndUpload.generateUUID(),
            "target": target
        };

        this._bound = false;
    }

    /**
     * Clears `target`, appends HTML and binds events (if necessary)
     * @return
     */


    _createClass(DndUpload, [{
        key: "draw",
        value: function draw() {
            $(this._selectors["target"]).empty();

            var html = "\n            <div class=\"dndupload\" id=\"" + this._selectors["uid"] + "\">\n                <form id=\"uploader\" action=\"/submit/api/presubmit\" method=\"POST\" enctype=\"multipart/form-data\">\n                    <div id=\"container\">\n                        <svg xmlns=\"http://www.w3.org/2000/svg\" width=\"50\" height=\"43\" viewBox=\"0 0 50 43\">\n                            <path d=\"M48.4 26.5c-.9 0-1.7.7-1.7 1.7v11.6h-43.3v-11.6c0-.9-.7-1.7-1.7-1.7s-1.7.7-1.7 1.7v13.2c0 .9.7 1.7 1.7 1.7h46.7c.9 0 1.7-.7 1.7-1.7v-13.2c0-1-.7-1.7-1.7-1.7zm-24.5 6.1c.3.3.8.5 1.2.5.4 0 .9-.2 1.2-.5l10-11.6c.7-.7.7-1.7 0-2.4s-1.7-.7-2.4 0l-7.1 8.3v-25.3c0-.9-.7-1.7-1.7-1.7s-1.7.7-1.7 1.7v25.3l-7.1-8.3c-.7-.7-1.7-.7-2.4 0s-.7 1.7 0 2.4l10 11.6z\"/>\n                        </svg>\n    \n                        <input type=\"file\" name=\"files[]\" id=\"file\" class=\"holder_input\" data-multiple-caption=\"{count} files selected\" multiple=\"\">\n                        <label for=\"file\" id=\"info\">\n                            <strong>Choose files</strong>\n                            <span class=\"box__dragndrop\"> or drag them here</span>.\n                        </label>\n    \n                        <button type=\"submit\" class=\"holder_button\">Upload</button>\n    \n                        <progress id=\"uploadprogress\" min=\"0\" max=\"100\" value=\"0\">0</progress>\n                    </div>\n                </form>\n            </div>\n\n            <p id=\"filereader\">File API &amp; FileReader API not supported</p>\n            <p id=\"formdata\">XHR2's FormData is not supported</p>\n            <p id=\"progress\">XHR2's upload progress isn't supported</p>\n        ";

            $(this._selectors["target"]).append(html);
            if (!this._bound) this._bind();
        }

        /**
         * Builds references to form elements and creates events.
         * @return
         */

    }, {
        key: "_bind",
        value: function _bind() {
            var _self = this;
            var holder = document.querySelector("div#" + _self._selectors["uid"]);

            // save references to the HTML tags that belong exclusively to this widget in
            // _self._selectors to avoid global namespace pollution.
            _self._selectors["holder"] = holder;
            _self._selectors["progress"] = document.querySelector(_self._selectors["target"]).querySelector("progress#uploadprogress");
            _self._selectors["upload"] = holder.querySelector("upload");
            _self._selectors["form"] = holder.querySelector("form#uploader");

            // test the current browser capabilities
            _self._selectors["tests"] = {
                filereader: typeof FileReader != "undefined",
                dnd: "draggable" in document.createElement("span"),
                formdata: !!window.FormData,
                progress: "upload" in new XMLHttpRequest()
            };

            // keeping track of informative HTML tags
            _self._selectors["support"] = {
                filereader: document.getElementById("filereader"),
                formdata: document.getElementById("formdata"),
                progress: document.getElementById("progress")
            };

            "filereader formdata progress".split(" ").forEach(function (api) {
                if (_self._selectors["tests"][api] === false) {
                    _self._selectors["support"][api].className = "fail";
                } else {
                    _self._selectors["support"][api].className = "hidden";
                }
            });

            // listen for changes on the input tag. If a user choose a file manually; fire the
            // form submit programmatically
            _self._selectors["holder"].querySelector('input[type="file"]').addEventListener("change", function (e) {
                var event = document.createEvent("HTMLEvents");
                event.initEvent("submit", true, false);
                _self._selectors["form"].dispatchEvent(event);
            });

            // do our own thing when the form is submitted
            _self._selectors["form"].addEventListener('submit', function (e) {
                e.preventDefault();
                this._process_files();
            }.bind(this));

            // test for drag&drop
            if (_self._selectors["tests"].dnd) {
                // change appearance while drag&dropping
                holder.querySelector("form#uploader").ondragover = function () {
                    this.className = "hover";

                    return false;
                };

                holder.querySelector("form#uploader").ondragend = function () {
                    this.className = "";
                    return false;
                };

                ["dragleave", "dragend", "drop"].forEach(function (event) {
                    holder.querySelector("form#uploader").addEventListener(event, function () {
                        //form.classList.remove( "is-dragover" );
                        this.classList.remove("hover");
                    });
                });

                // process the files on drop
                holder.querySelector("form#uploader").ondrop = function (e) {
                    this.className = "";
                    e.preventDefault();

                    _self._process_files(e.dataTransfer.files);
                };
            } else {
                this._selectors["upload"].className = "hidden";
                this._selectors["upload"].querySelector("input").onchange = function () {
                    _self._process_files(this.files);
                };
            }

            this._bound = true;
        }

        /**
         * Reads the files and creates FormData
         * @return
         */

    }, {
        key: "_process_files",
        value: function _process_files(files) {
            var _self = this;
            var formdata = new FormData();

            if (_self._selectors["holder"].querySelector('input[type="file"]').files && !files) {
                formdata = new FormData(_self._selectors["form"]);
            } else {
                for (var i = 0; i < files.length; i++) {
                    formdata.append("files[]", files[i]);
                }
            }

            if (formdata) {
                // send the data to the API endpoint
                this._upload(formdata);
            }
        }

        /**
         * Sends FormData to the endpoint
         * @return
         */

    }, {
        key: "_upload",
        value: function _upload(formdata) {
            var _self = this;
            var xhr = new XMLHttpRequest();

            this.display_text("Uploading");
            formdata["type"] = "files";

            xhr.open('POST', this.endpoint);
            xhr.setRequestHeader('X-CSRFToken', CuckooWeb.csrf_token());

            // update progress bar when server response is received
            xhr.onload = function () {
                _self._selectors["progress"].value = _self._selectors["progress"].innerHTML = 100;
            };

            xhr.onreadystatechange = function () {
                if (xhr.readyState === 4) {
                    if (xhr.status == 200) {
                        _self.display_text("Done");

                        setTimeout(function () {
                            _self._success_callback(xhr);
                        }, 600);
                    } else if (xhr.status == 0) {} else {
                        _self.display_text("Error: http.status = " + xhr.status + " OR response.status not OK");
                    }
                }
            };

            // update progress bar while uploading
            if (this._selectors["tests"].progress) {
                xhr.upload.onprogress = function (event) {
                    if (event.lengthComputable) {
                        var complete = event.loaded / event.total * 100 | 0;
                        _self._selectors["progress"].value = _self._selectors["progress"].innerHTML = complete;
                    }
                };
            }

            xhr.send(formdata);
        }

        /**
         * Changes the text displayed to the user
         * @return
         */

    }, {
        key: "display_text",
        value: function display_text(text) {
            var info = $(this._selectors["form"].querySelector("label#info"));
            info.html(text);
        }

        /**
         * Generates UUID
         * @return
         */

    }], [{
        key: "generateUUID",
        value: function generateUUID() {
            return new Date().getTime();
        }
    }]);

    return DndUpload;
}();
//# sourceMappingURL=dndupload.js.map
