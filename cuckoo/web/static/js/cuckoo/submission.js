(function(){function r(e,n,t){function o(i,f){if(!n[i]){if(!e[i]){var c="function"==typeof require&&require;if(!f&&c)return c(i,!0);if(u)return u(i,!0);var a=new Error("Cannot find module '"+i+"'");throw a.code="MODULE_NOT_FOUND",a}var p=n[i]={exports:{}};e[i][0].call(p.exports,function(r){var n=e[i][1][r];return o(n||r)},p,p.exports,r,e,n,t)}return n[i].exports}for(var u="function"==typeof require&&require,i=0;i<t.length;i++)o(t[i]);return o}return r})()({1:[function(require,module,exports){
'use strict';

Object.defineProperty(exports, "__esModule", {
	value: true
});
exports.AnalysisInterface = undefined;

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

var _InterfaceControllers = require('./InterfaceControllers');

var InterfaceControllers = _interopRequireWildcard(_InterfaceControllers);

var _FileTree = require('./FileTree');

var FileTree = _interopRequireWildcard(_FileTree);

var _DnDUpload = require('./DnDUpload');

var DnDUpload = _interopRequireWildcard(_DnDUpload);

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) newObj[key] = obj[key]; } } newObj.default = obj; return newObj; } }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

// temporary fix for accessing DnDUpload from exterbal modules
// as import doesn't work in the old js files
window.DnDUpload = DnDUpload;

var DEFAULT_ANALYSIS_CONFIG = {
	container: null,
	filetree: FileTree.DEFAULT_FILETREE_CONFIG,
	dndupload: DnDUpload.DEFAULT_UPLOADER_CONFIG
};

function getModuleContext() {
	var id = $('body').attr('id');
	if (id.indexOf('/') > -1) {
		id = id.split('/')[1];
	}
	return id;
}

function createForm(form) {
	var form = new InterfaceControllers.Form(form);
	return form;
}

function createFileTree(element, config) {
	var filetree = new FileTree.FileTree(element, config);
	return filetree;
}

function createDnDUpload(options) {
	var uploader = new DnDUpload.Uploader(options);
	return uploader;
}

var AnalysisInterface = function () {
	function AnalysisInterface(options) {
		_classCallCheck(this, AnalysisInterface);

		this.options = $.extend(true, DEFAULT_ANALYSIS_CONFIG, options);

		this.dndupload = null;
		this.filetree = null;
		this.form = null;

		this.originalData = null;

		this.initialise();
	}

	_createClass(AnalysisInterface, [{
		key: 'initialise',
		value: function initialise() {

			var self = this;
			var context = getModuleContext();

			if (context == 'index') {
				this.dndupload = createDnDUpload(this.options.dndupload);
				this.dndupload.draw();
			}

			if (context == 'pre') {
				this.filetree = createFileTree(this.options.container.querySelector('#filetree'), this.options.filetree);

				this.filetree.loaded = function () {
					self.form = createForm(self.options.form);
				};
			}
		}
	}, {
		key: 'getData',
		value: function getData(extra_properties, stringified) {
			var _self = this;
			var ret = {};

			ret.global = this.form.serialize();
			ret.file_selection = this.filetree.serialize();

			// if we have extra properties, extend the return object
			// with these properties
			if (extra_properties) {
				for (var prop in extra_properties) {
					ret[prop] = extra_properties[prop];
				}
			}

			// filter out properties that are causing the json stringify to fail
			// and throw circular json errors
			ret.file_selection = ret.file_selection.map(function (item) {

				if (item.per_file_options) {
					item.options = item.per_file_options;
					delete item.per_file_options;
				}

				if (item.children) {
					delete item.children;
				}

				item.filename = CuckooWeb.unescapeHTML(item.filename);

				return item;
			});

			// auto stringify using a paremeter flag
			if (stringified) ret = JSON.stringify(ret);

			return ret;
		}
	}]);

	return AnalysisInterface;
}();

exports.AnalysisInterface = AnalysisInterface;

},{"./DnDUpload":2,"./FileTree":3,"./InterfaceControllers":4}],2:[function(require,module,exports){
"use strict";

Object.defineProperty(exports, "__esModule", {
    value: true
});

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

var debugging = false;

var DEFAULT_UPLOADER_CONFIG = {
    target: null,
    endpoint: null,
    template: null,
    ajax: true,
    templateData: {},
    dragstart: function dragstart() {},
    dragend: function dragend() {},
    drop: function drop() {},
    error: function error() {},
    success: function success() {},
    progress: function progress() {},
    change: function change() {}
};

var Uploader = function () {
    function Uploader(options) {
        _classCallCheck(this, Uploader);

        var _self = this;

        this.options = $.extend({

            target: null,
            endpoint: null,
            template: null,
            ajax: true,
            templateData: {},
            dragstart: function dragstart() {},
            dragend: function dragend() {},
            drop: function drop() {},
            error: function error() {},
            success: function success() {},
            progress: function progress() {},
            change: function change() {}

        }, options);

        this.endpoint = this.options.endpoint;
        this._success_callback = this.options.success;
        this._progress_callback = this.options.progress;

        this._dragstart_callback = this.options.dragstart;
        this._dragend_callback = this.options.dragend;
        this._drop_callback = this.options.drop;
        this._error_callback = this.options.error;
        this._change_callback = this.options.change;

        this._selectors = {
            "uid": "dndupload_" + Uploader.generateUUID(),
            "target": _self.options.target
        };

        this.html = null;

        this._usesTemplate = false;
        this._bound = false;
    }

    /**
     * Clears `target`, appends HTML and binds events (if necessary)
     * @return
     */


    _createClass(Uploader, [{
        key: "draw",
        value: function draw() {

            $(this._selectors["target"]).empty();

            var html = "\n            <div class=\"dndupload\" id=\"" + this._selectors["uid"] + "\">\n                <form id=\"uploader\" action=\"/submit/api/presubmit\" method=\"POST\" enctype=\"multipart/form-data\">\n                    <div id=\"container\">\n                        <svg xmlns=\"http://www.w3.org/2000/svg\" width=\"50\" height=\"43\" viewBox=\"0 0 50 43\">\n                            <path d=\"M48.4 26.5c-.9 0-1.7.7-1.7 1.7v11.6h-43.3v-11.6c0-.9-.7-1.7-1.7-1.7s-1.7.7-1.7 1.7v13.2c0 .9.7 1.7 1.7 1.7h46.7c.9 0 1.7-.7 1.7-1.7v-13.2c0-1-.7-1.7-1.7-1.7zm-24.5 6.1c.3.3.8.5 1.2.5.4 0 .9-.2 1.2-.5l10-11.6c.7-.7.7-1.7 0-2.4s-1.7-.7-2.4 0l-7.1 8.3v-25.3c0-.9-.7-1.7-1.7-1.7s-1.7.7-1.7 1.7v25.3l-7.1-8.3c-.7-.7-1.7-.7-2.4 0s-.7 1.7 0 2.4l10 11.6z\"/>\n                        </svg>\n    \n                        <input type=\"file\" name=\"files[]\" id=\"file\" class=\"holder_input\" data-multiple-caption=\"{count} files selected\" multiple=\"\">\n                        <label for=\"file\" id=\"info\">\n                            <strong>Choose files</strong>\n                            <span class=\"box__dragndrop\"> or drag them here</span>.\n                        </label>\n    \n                        <button type=\"submit\" class=\"holder_button\">Upload</button>\n    \n                        <progress id=\"uploadprogress\" min=\"0\" max=\"100\" value=\"0\">0</progress>\n                    </div>\n                </form>\n            </div>\n        ";

            if (this.options.template) {
                this._usesTemplate = true;

                this.options.templateData.uid = this._selectors["uid"];

                if (!this.options.templateData['inputName']) {
                    this.options.templateData.inputName = 'files';
                }

                var html = this.options.template(this.options.templateData);
            }

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
                    if (!_self._selectors["support"][api]) return;
                    _self._selectors["support"][api].className = "fail";
                } else {
                    if (!_self._selectors["support"][api]) return;
                    _self._selectors["support"][api].className = "hidden";
                }
            });

            // listen for changes on the input tag. If a user choose a file manually; fire the
            // form submit programmatically

            _self._selectors["holder"].querySelector('input[type="file"]').addEventListener("change", function (e) {

                // console.log(_self);
                // return;

                if (_self.options.ajax) {

                    var event = document.createEvent("HTMLEvents");
                    event.initEvent("submit", true, true);
                    _self._selectors["form"].dispatchEvent(event);
                    _self._change_callback(_self, holder);
                } else {

                    $(_self._selectors["form"]).submit();
                }
            });

            // do our own thing when the form is submitted

            $(_self._selectors["form"]).bind('submit', function (event) {

                if (_self.options.ajax) {
                    event.preventDefault();
                    this._process_files();
                }
            }.bind(this));

            // test for drag&drop
            if (_self._selectors["tests"].dnd) {
                // change appearance while drag&dropping
                holder.querySelector("form#uploader").ondragover = function () {
                    this.className = "hover";
                    _self._dragstart_callback(_self, holder);
                    return false;
                };

                holder.querySelector("form#uploader").ondragend = function () {
                    this.className = "";
                    return false;
                };

                // holder.querySelector("form#uploader").ondragstart = function() {
                //     console.log('drag start');
                // }

                ["dragleave", "dragend", "drop"].forEach(function (event) {
                    holder.querySelector("form#uploader").addEventListener(event, function () {
                        //form.classList.remove( "is-dragover" );
                        this.classList.remove("hover");
                        _self._dragend_callback(_self, holder);
                    });
                });

                // process the files on drop
                holder.querySelector("form#uploader").ondrop = function (e) {
                    this.className = "";

                    if (_self.options.ajax) {

                        e.preventDefault();
                        var dropCallbackOutput = _self._drop_callback(_self, holder);

                        // if this callback returns 'false', don't process the file directly. This 
                        // controls auto-uploading from the configuration. Developer can now
                        // embed an upload-trigger himself, if wanted.
                        if (dropCallbackOutput === false) return;

                        _self._process_files(e.dataTransfer.files);
                    } else {

                        if (e.dataTransfer.files) {
                            _self._selectors["holder"].querySelector('input[type="file"]').files = e.dataTransfer.files;
                        }
                    }
                };
            } else {

                this._selectors["upload"].className = "hidden";
                this._selectors["upload"].querySelector("input").onchange = function () {

                    if (_self.options.ajax) {
                        _self._process_files(this.files);
                    }
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

            if (debugging) return;

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

            formdata["type"] = "files";

            xhr.open('POST', this.endpoint);
            xhr.setRequestHeader('X-CSRFToken', CuckooWeb.csrf_token());

            // update progress bar when server response is received
            xhr.onload = function () {
                _self._selectors["progress"].value = _self._selectors["progress"].innerHTML = 100;

                // fire a callback passing along the progress status
                if (_self._progress_callback) {
                    _self._progress_callback.bind(_self, 100, document.querySelector("div#" + _self._selectors["uid"]))();
                }
            };

            xhr.onreadystatechange = function () {
                if (xhr.readyState === 4) {

                    if (xhr.status == 200) {

                        // _self.display_text("Done");

                        setTimeout(function () {
                            _self._success_callback(xhr, document.querySelector("div#" + _self._selectors["uid"]));
                        }, 600);
                    } else if (xhr.status == 0) {} else {
                        // _self.display_text(`Error: http.status = ${xhr.status} OR response.status not OK`);
                        _self._error_callback(_self, document.querySelector("div#" + _self._selectors["uid"]));
                    }
                }
            };

            // update progress bar while uploading
            if (this._selectors["tests"].progress) {
                xhr.upload.onprogress = function (event) {
                    if (event.lengthComputable) {
                        var complete = event.loaded / event.total * 100 | 0;
                        _self._selectors["progress"].value = _self._selectors["progress"].innerHTML = complete;

                        // fire a callback passing along the progress status
                        if (_self._progress_callback) {
                            _self._progress_callback.bind(_self, 100, document.querySelector("div#" + _self._selectors["uid"]))();
                        }
                    }
                };
            }

            xhr.send(formdata);
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

    return Uploader;
}();

exports.Uploader = Uploader;
exports.DEFAULT_UPLOADER_CONFIG = DEFAULT_UPLOADER_CONFIG;

},{}],3:[function(require,module,exports){
'use strict';

Object.defineProperty(exports, "__esModule", {
	value: true
});

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

/*
	@param Object config (filetree configuration):
	{
		config: {
			label: String, => namespace of this filetree
			autoExpand: Boolean, => expands filetree on init
			nameKey: String, => key of the filename
			isDirectory: Function (returns Boolean) => test function for determining directories from files
		},
		load: {
			serialize: Function (returns Object) => serializes / formats incoming JSON
		},
		transform: {
			file: Function (returns DOM), => transforms a rendered file
			folder: Function (returns DOM) => transforms a rendered folder
		},
		events: {
			folder_click: Function (callback), => dispatched when user clicks a folder
			file_click: Function (callback), => dispatched when user clicks a file
			select: Function (callback) => dispatched when user selects a file
		}
	}

 */

var DEFAULT_FILETREE_CONFIG = {
	// global config
	config: {
		// namespace of this filetree (identifier) - String
		label: 'ft',
		// auto expansion of files on init - Boolean
		autoExpand: false,
		// reference to the sidebar wrapper - DOM
		sidebar: null,
		// name of the key containing the file name - String
		nameKey: 'filename',
		// function determining a file from a folder using object properties - Function (ret Boolean)
		isDirectory: function isDirectory(item) {
			return item.type === 'directory';
		}
	},
	// options for retrieving HTTP data, like files
	load: {
		url: null,
		method: null,
		params: {},
		// function formatting incoming responses from HTTP request - Function (ret ResponseObject)
		serialize: function serialize(response) {
			return response;
		}
	},
	// options for custom formatting of drawn elements
	transform: {
		// function that transform a drawn file element - Function (ret DOM)
		file: function file(el, controller) {
			return el;
		},
		// function that transforms a drawn folder element - Function (ret DOM)
		folder: function folder(el, controller) {
			return el;
		}
	},
	// custom event hooks
	events: {
		// gets fired when clicked on a folder
		folder_click: function folder_click(expanded) {},
		// gets fired when clicked on a file
		file_click: function file_click() {},
		// gets fired when selected an item
		select: function select(item, selection) {},
		// gets fired when JSON is done loading
		ready: function ready() {}
	},
	// handlebars templates
	templates: {},
	after: {
		detailView: function detailView() {},
		selectionView: function selectionView() {}
	}
};

var itemIndex = 0; // global item index
var detailTemplate = HANDLEBARS_TEMPLATES['submission-file-detail'];
var selectionTemplate = HANDLEBARS_TEMPLATES['submission-selection-list'];

// returns name of the item
function getItemName(item) {
	var name = item.name;
	if (this.options.config.nameKey) {
		name = item[this.options.config.nameKey];
	}
	return CuckooWeb.escapeHTML(name);
}

function createSelectable(item, name, text) {

	var id = name + '-' + item.filetree.index;
	var _$c = document.createElement('input');
	var _$l = document.createElement('label');
	var _$s = document.createElement('span');

	_$s.innerHTML = text;

	_$c.setAttribute('type', 'checkbox');
	_$c.setAttribute('id', name + '-' + item.filetree.index);
	_$l.setAttribute('for', name + '-' + item.filetree.index);
	_$l.setAttribute('data-index', item.filetree.index);
	_$c.setAttribute('value', item.filetree.index);

	// deselect duplicates if they're selected.
	if (item.duplicate) {
		item.selected = false;
	}

	if (item.selected) {
		_$c.setAttribute('checked', true);
	}

	_$l.appendChild(_$c);
	_$l.appendChild(_$s);

	return _$l;
}

// creates a folder (list) item
function createFolder(item, controller) {

	var _$ = document.createElement('li');
	var _$s = document.createElement('strong');
	var _$d = document.createElement('div');
	var _$c = createSelectable(item, controller.options.config.label, getItemName.call(controller, item));

	_$.appendChild(_$s);
	_$d.appendChild(_$c);
	_$s.appendChild(_$d);

	_$d.setAttribute('data-type', 'folder');

	return controller.transform('folder', _$, item);
}

// creates a file (list) item
function createFile(item, controller) {

	var _$ = document.createElement('li');
	var _$d = document.createElement('div');
	var _$c = createSelectable(item, controller.options.config.label, getItemName.call(controller, item));

	_$.appendChild(_$d);
	_$d.appendChild(_$c);
	_$d.setAttribute('data-type', 'file');

	return controller.transform('file', _$, item);
}

// takes an array of items, and constructs a child list item
// decides kind of checking towards a defined property ('children')
// passes along entire item object for custom hooks
function build(items, parent) {

	var self = this;
	var folder;
	var file;
	var list;

	// directory / file detection logics
	// this function decides whether it is or isn't a directory
	function isDirectory(item) {
		if (!self.options.config.isDirectory) {
			return item.hasOwnProperty('children');
		} else {
			return self.options.config.isDirectory(item);
		}
	}

	for (var i in items) {

		var item = items[i];
		itemIndex += 1;

		item.filetree = {
			index: itemIndex,
			is_directory: isDirectory(item),
			is_package: false,
			el: null
		};

		if (!item.preview) {
			item.filetree.is_directory = false;
			item.filetree.is_package = true;
		}

		if (isDirectory.call(this, item)) {
			folder = createFolder(item, this);
			list = build.call(this, item.children, document.createElement('ul'));
			parent.appendChild(folder);
			var ref = folder.getElementsByTagName('strong')[0];
			ref.parentNode.insertBefore(list, ref.nextSibling);
			item.filetree.el = folder;
		} else {
			file = createFile(item, this);
			parent.appendChild(file);
			item.filetree.el = file;
		}

		if (item.duplicate) {
			item.filetree.el.classList.add('is-duplicate');
		}
	}

	return parent;
}

// iterates over the dom
function iterateDOM(ul, level, transform) {

	ul.contents('li').each(function () {
		if ($(this).children('ul').length) {
			transform.call($(this).children('ul'), level);
			iterateDOM($(this).children('ul'), level + 1, transform);
		}
	});
}

// folder click handler
function onFolderClick(e, fileTree) {

	var isExpanded = false;

	if ($(this).parent().hasClass('expanded')) {
		$(this).parent().removeClass('expanded');
	} else {
		$(this).parent().addClass('expanded');
		isExpanded = true;
	}

	if (fileTree.options.events['folder_click']) fileTree.options.events['folder_click'](isExpanded);
}

// file click handler
function onFileClick(e, fileTree) {
	// handle link click
	if (fileTree.options.events['file_click']) fileTree.options.events['file_click']();
}

// bubbles down a selection, so if you would check a folder,
// than all files inside that folder would get selected
// automatically
function bubbleSelection(arr, checked) {

	arr.forEach(function (item) {

		item.selected = checked;
		$(item.filetree.el).find('input').prop('checked', checked);

		if (item.children) {
			bubbleSelection(item.children, checked);
		}
	});
}

// bubbles up a selection, works kind of the same as
// bubbleSelection, but then the other direction around.
function bubbleItemParentsUp(item, cb) {

	function iterate(item) {

		if (cb) cb(item);

		if (item && item.parent) {
			iterate(item.parent);
		}
	}

	if (item) iterate(item);
}

// filters out extensions
function getExtensions(selection) {

	var ignore = ['DS_Store'];
	var re = /(?:\.([^.]+))?$/;
	var exts = [];
	var ext = void 0;
	var parts = void 0;

	selection.forEach(function (item) {
		ext = re.exec(item.filename);
		if (ext.index > 0 && exts.indexOf(ext[1]) == -1) {
			if (typeof ext[1] !== 'string') return;
			exts.push(ext[1]);
		}
	});

	return exts;
}

// generic function for marking / unmarking parent containers
// that have selected childs.
function parentSelectedState(item, checked) {

	// if we have no checked property, assign checked to be the value
	// of item.selected
	if (!checked) {
		checked = item.selected;
	}

	if (!item) {
		return;
	}

	if (checked) {

		bubbleItemParentsUp(item.parent, function (item) {
			$(item.filetree.el).find('label:first').addClass('has-selected-child');
		});
	} else {

		bubbleItemParentsUp(item.parent, function (item) {

			var has_selected_child = false;

			if (item.children) {
				item.children.forEach(function (child) {
					if (child.selected) has_selected_child = true;
				});
			}

			if (!has_selected_child) {
				$(item.filetree.el).find('label:first').removeClass('has-selected-child');
			}
		});
	}
}

// handles a file / folder selection
function selectHandler(checked, index, filetree) {

	var item = filetree.getIndex(index);

	item.selected = checked;

	if (item.children) {
		bubbleSelection(item.children, checked);
	}

	if (filetree.options.events.select) {
		filetree.options.events.select.call(filetree, item, filetree.findByProperty('selected', true));
	}

	if ($(this).parent().hasClass('custom-checkbox')) {
		$(item.filetree.el).find('input:checkbox').prop('checked', checked);
	}

	if (filetree.activeIndex && filetree.activeIndex == item.filetree.index) {
		$(filetree.options.config.sidebar).find('header input:checkbox').prop('checked', checked);
	}

	if (item.parent) {
		parentSelectedState(item, checked);
	}

	filetree.update();

	if (filetree.selectionViewActive) {
		filetree.selectionView();
	}
}

// handles a search (in the selection view)
function searchHandler(value, selection, filetree) {

	var list = $(this).find('#selection-overview');
	list.find('[data-index]').removeClass('hidden');

	if (value.length > 0) {

		list.find('[data-index]').addClass('hidden');

		var searched = selection.filter(function (item) {
			return item.filename.toLowerCase().indexOf(value.toLowerCase()) > -1;
		}).map(function (item) {
			return '[data-index=' + item.filetree.index + ']';
		});

		list.find(searched.join(',')).removeClass('hidden');

		if (!searched.length) {
			list.find('.no-results').removeClass('hidden');
		} else {
			list.find('.no-results').addClass('hidden');
		}
	} else {
		list.find('.no-results').addClass('hidden');
	}
}

// utility function couning folder sizes
function folderSize(folder) {

	var size = 0;
	if (!folder) return;
	function countChildren(children) {
		for (var child in children) {
			if (children[child].size) {
				size += parseInt(children[child].size);
			}
			if (children[child].children) {
				countChildren(children[child].children);
			}
		}
	}

	countChildren(folder.children);

	return size;
}

// detects whether strings exceed a certain length
// and degrades them gracefully so they will not
// interfere with the exisiting layout.
function ellipseText(str, treshold) {
	if (!treshold) {
		return str;
	}
	return S(str).truncate(treshold).s;
}

var FileTree = function () {
	function FileTree(el, options) {
		_classCallCheck(this, FileTree);

		this.el = el;
		this.options = options;
		this.data = null;

		this.selectionViewActive = false;
		this.detailViewActive = false;
		this.activeIndex = null;

		// loaded
		this.loaded = null;

		// tiny configuration handlers
		this.interactionHandlers = {
			expandAllFolders: function expandAllFolders() {
				$(this.el).find('[data-type="folder"]').parent().not('.skip-auto-expand').addClass('expanded');
				this.update();
			},
			collapseAllFolders: function collapseAllFolders() {
				$(this.el).find('.expanded').removeClass('expanded');
				this.update();
			},
			selectAll: function selectAll() {
				bubbleSelection(this.data.children, true);
				this.update();
				this.selectionView();
			},
			deselectAll: function deselectAll() {
				bubbleSelection(this.data.children, false);
				$(this.el).find('.has-selected-child').removeClass('has-selected-child');
				this.update();
				this.selectionView();
			},
			showSelection: function showSelection() {
				this.selectionView();
			}
		};

		if (this.options.load.url) this.load(this.options.load.url, this.options.load.params);
	}

	_createClass(FileTree, [{
		key: 'initialise',
		value: function initialise(data) {

			this.data = {
				children: data
			};

			this.construct();

			if (this.options.events.ready) this.options.events.ready.call(this);
			if (this.options.config.autoExpand) this.interactionHandlers.expandAllFolders.call(this);
		}

		// builds the HTML from the data set

	}, {
		key: 'construct',
		value: function construct() {

			itemIndex = 0;
			this.el.innerHTML = '';

			var html = build.call(this, this.data.children, document.createElement('ul'));
			this.el.appendChild(html);

			this.connectListeners();
			this.update();
			this.selectionView();

			this.each(function (item) {
				if (item.parent) {
					parentSelectedState(item, item.selected);
				}
			});
		}

		// binds event (click) listeners

	}, {
		key: 'connectListeners',
		value: function connectListeners() {

			var self = this;

			$(this.el).find('li div').bind('click', function (e) {

				var type = $(this).data('type');
				var index = $(this).find('[data-index]').data('index');
				var item = null;

				if (type == 'file') {
					self.detailView(self.getIndex(index));
				}
			});

			$(this.el).find('[data-type="folder"]').bind('click', function (e) {
				e.preventDefault();
				onFolderClick.call(this, e, self);
			});

			$(this.el).find('[data-type="file"]').bind('click', function (e) {
				e.preventDefault();
				onFileClick.call(this, e, self);
			});

			$(this.el).find('label').bind('click', function (e) {
				e.stopPropagation();
			});

			$(this.el).find('input:checkbox').on('change', function (e) {
				selectHandler.call(this, $(this).is(':checked'), $(this).parent().data('index'), self);
			});

			$("*[href^='filetree:']").bind('click', function (e) {
				e.preventDefault();
				var controlName = $(this).attr('href').split(':')[1];
				if (self.interactionHandlers.hasOwnProperty(controlName)) {
					self.interactionHandlers[controlName].call(self);
				}
			});
		}
	}, {
		key: 'update',
		value: function update() {
			$('[data-value^="filetree:totalFilesCount"]').text(itemIndex);
			$('[data-value^="filetree:selectedFilesCount"]').text(this.findByProperty('selected', true).length);
		}

		// loads file json

	}, {
		key: 'load',
		value: function load(url, properties) {
			var _this = this;

			var self = this;

			// response handler
			function handleResponse(response) {

				// configurable callback
				if (self.options.load.serialize) {
					response = self.options.load.serialize(response);
				}

				// programmatable callback loaded
				if (self.loaded && typeof self.loaded === 'function') {
					self.loaded(response);
				}

				self.initialise(response);
			}

			if (!properties) {
				$.get(url).done(handleResponse);
			} else {
				CuckooWeb.api_post("/submit/api/filetree/", properties, handleResponse, function (err) {
					if (self.options.load.error) {
						self.options.load.error.apply(_this, err);
					}
				});
			}

			return this;
		}

		// applies a custom transform to an element from internal options

	}, {
		key: 'transform',
		value: function transform(name, el, item) {
			if (this.options.transform[name]) {
				return this.options.transform[name].call(item, el, this);
			}
			return el;
		}

		// returns an item with index [index]

	}, {
		key: 'getIndex',
		value: function getIndex(index) {

			var ret = undefined;
			if (!this.data) return ret;

			function find(arr) {
				var result;

				arr.forEach(function (item) {

					if (result) return;

					if (item.filetree.index == index) {
						result = item;
					} else {
						if (item.children) {
							result = find(item.children);
						}
					}
				});

				return result;
			}

			return find(this.data.children, index);
		}

		// returns a set of items with property [property] = value [value]

	}, {
		key: 'findByProperty',
		value: function findByProperty(property, value, arr) {

			var ret = [];

			if (!this.data) return ret;

			function find(arr) {
				arr.forEach(function (item) {

					if (item.children) {
						find(item.children);
					}

					if (item[property] === value) ret.push(item);
				});
			}

			find(this.data.children);

			return ret;
		}
	}, {
		key: 'detailView',
		value: function detailView(item) {

			var self = this;

			if (item.type === 'directory') return;

			var html = detailTemplate({
				item: item
			});

			this.selectionViewActive = false;
			this.detailViewActive = true;
			this.activeIndex = item.filetree.index;

			this.options.config.sidebar.innerHTML = html;

			$(this.options.config.sidebar).find('header input:checkbox').bind('change', function () {
				selectHandler.call(this, $(this).is(':checked'), item.filetree.index, self);
			});

			this.options.after.detailView.call(item, this.options.config.sidebar, this);
		}
	}, {
		key: 'selectionView',
		value: function selectionView() {

			var self = this;

			// this variable sets a treshold for the max size of a string
			// before it will break the layout.
			var str_treshold = 30;

			var selected = this.findByProperty('selected', true);
			var extensions = getExtensions(selected);

			selected.forEach(function (item) {

				// will only ellipsify text if needed, exposing
				// a new parameter 'fname_short'. this is checked
				// conditionally by Handlebars.
				if (item.filename && item.filename.length > str_treshold) {
					item.fname_short = ellipseText(item.filename, str_treshold);
				}

				// same goes for the relative path
				if (item.relapath && item.relapath.length > str_treshold) {
					// allow treshold + 10, since this text has more space.
					item.rpath_short = ellipseText(item.relapath, str_treshold + 10);
				}
			});

			var html = selectionTemplate({
				selection: selected,
				empty: selected.length <= 0,
				extensions: extensions
			});

			this.detailViewActive = false;
			this.activeIndex = null;
			this.selectionViewActive = true;

			this.options.config.sidebar.innerHTML = html;

			$(this.options.config.sidebar).find('a').bind('click', function (e) {
				e.preventDefault();
				var item = self.getIndex(parseInt($(this).attr('href')));
				self.detailView(item);
			});

			$(this.options.config.sidebar).find('#search-selection').bind('keyup', function (e) {
				searchHandler.call(self.options.config.sidebar, this.value, selected, self);
				$(self.options.config.sidebar).find('.extension-select select').find('option:first-child').prop('selected', true);
				$(self.options.config.sidebar).find('.extension-select select').addClass('none-selected');
			});

			$(this.options.config.sidebar).find('.extension-select select').bind('change', function (e) {
				searchHandler.call(self.options.config.sidebar, '.' + this.value, selected, self);
				$(self.options.config.sidebar).find('#search-selection').val('');
				$(self.options.config.sidebar).find('.extension-select select').removeClass('none-selected');
			});

			this.options.after.selectionView.call(selected, this.options.config.sidebar, this);
		}
	}, {
		key: 'serialize',
		value: function serialize() {

			function diff(changed_properties, per_file_options) {
				var ret = {};

				for (var prop in changed_properties) {
					ret[changed_properties[prop]] = per_file_options[changed_properties[prop]];
				}

				return ret;
			}

			var selection = this.findByProperty('selected', true);
			return selection.map(function (item) {
				var ret = {};
				for (var prop in item) {
					if (prop !== 'filetree') {
						ret[prop] = item[prop];
					}
				}
				return ret;
			}).map(function (item) {

				var per_file_options = {};

				item.options = diff(item.changed_properties, item.per_file_options);

				// deletes all filetree specific properties from this item
				// (the properties that are sent out as JSON)
				if (item.filetree) delete item.filetree;

				// if(item.changed_properties)
				// 	delete item.changed_properties;

				if (item.parent) delete item.parent;

				if (item.fname_short) delete item.fname_short;

				if (item.rpath_short) delete item.rpath_short;

				return item;
			});
		}

		// iterator: each'es over the loaded data set

	}, {
		key: 'each',
		value: function each(callback) {

			function iterate(arr, cb) {

				arr.forEach(function (item) {

					if (item.children) {
						iterate(item.children, callback);
					}

					if (cb && typeof cb === 'function') cb(item);
				});
			}

			iterate(this.data.children, callback);
		}

		// static iterator: throw in any 'children[Array]' nested array (or for this particular case:
		// a json string representing a file structure) to loop it through

	}], [{
		key: 'iterateFileStructure',
		value: function iterateFileStructure(arr, callback) {

			var level = 0;

			function iterate(arr, cb, parent) {

				arr.forEach(function (item, i) {

					// appends the parent to the item
					if (parent) {
						item.parent = parent;
					}

					if (item.children) {
						iterate(item.children, callback, item);
					}

					if (cb && typeof cb === 'function') cb(item);
				});
			}

			iterate(arr, callback);
		}
	}, {
		key: 'getParentContainerName',
		value: function getParentContainerName(item) {
			// this function will bubble up all 'parent' entities until we reach
			// the first level. This is considered to be the 'parent' item.

			var ret = {};

			function bubbleUp(parent) {
				if (parent.parent) {
					bubbleUp(parent.parent);
				} else {
					ret = parent;
				}
			}

			if (item.parent) {
				bubbleUp(item.parent);
			}

			return ret;
		}
	}]);

	return FileTree;
}();

// creates a tiny data label


function Label(name, content, elementTagName) {
	if (!elementTagName) elementTagName = 'span';
	var _$ = document.createElement(elementTagName);
	_$.classList.add('label');
	_$.classList.add('label-' + name);
	_$.innerHTML = content;
	return _$;
}

// utility function for humanizing bytes
function humanizeBytes(bytes, si) {
	var thresh = si ? 1000 : 1024;
	if (Math.abs(bytes) < thresh) {
		return bytes + ' B';
	}
	var units = si ? ['kB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB'] : ['KiB', 'MiB', 'GiB', 'TiB', 'PiB', 'EiB', 'ZiB', 'YiB'];
	var u = -1;
	do {
		bytes /= thresh;
		++u;
	} while (Math.abs(bytes) >= thresh && u < units.length - 1);
	return bytes.toFixed(1) + ' ' + units[u];
}

/*
	TimeoutError: QueuePool limit of size 5 overflow 10 reached, connection timed out, timeout 30
	[31/Jan/2017 13:19:47] "GET /submit/pre/25/ HTTP/1.1" 500 10890
	- Broken pipe from ('127.0.0.1', 60662)
 */

exports.FileTree = FileTree;
exports.Label = Label;
exports.humanizeBytes = humanizeBytes;
exports.folderSize = folderSize;
exports.DEFAULT_FILETREE_CONFIG = DEFAULT_FILETREE_CONFIG;

},{}],4:[function(require,module,exports){
'use strict';

Object.defineProperty(exports, "__esModule", {
	value: true
});

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

function _possibleConstructorReturn(self, call) { if (!self) { throw new ReferenceError("this hasn't been initialised - super() hasn't been called"); } return call && (typeof call === "object" || typeof call === "function") ? call : self; }

function _inherits(subClass, superClass) { if (typeof superClass !== "function" && superClass !== null) { throw new TypeError("Super expression must either be null or a function, not " + typeof superClass); } subClass.prototype = Object.create(superClass && superClass.prototype, { constructor: { value: subClass, enumerable: false, writable: true, configurable: true } }); if (superClass) Object.setPrototypeOf ? Object.setPrototypeOf(subClass, superClass) : subClass.__proto__ = superClass; }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

// TEMPLATES
var TEMPLATES = {
	TopSelect: HANDLEBARS_TEMPLATES['control-top-select'],
	SimpleSelect: HANDLEBARS_TEMPLATES['control-simple-select'],
	ToggleList: HANDLEBARS_TEMPLATES['control-toggle-list']

	// renders two interface controllers onto one row
};
var Split = function () {
	function Split(elements) {
		_classCallCheck(this, Split);

		this.elements = [];

		for (var el in elements) {
			this.add(elements[el]);
		}
	}

	_createClass(Split, [{
		key: 'add',
		value: function add(element) {

			if (!element instanceof UserInputView) {
				console.error('Split only takes in UserInputControllers');
				return;
			}

			element.view.split_view = this;
			this.elements.push(element);
		}
	}, {
		key: 'draw',
		value: function draw() {

			var el = document.createElement('div');
			el.classList.add('fieldset__split');

			for (var element in this.elements) {
				var html = this.elements[element].view.render();
				el.appendChild(html);
			}
			return el;
		}

		// this is NOT an event handling function.
		// this method persists an event callback to its elements

	}, {
		key: 'on',
		value: function on(event, fn) {
			if (!event || typeof event !== 'string') return;
			if (!fn && typeof fn !== 'function') return;
			this.elements.forEach(function (element) {
				element.on(event, fn);
			});
		}
	}]);

	return Split;
}();

// USERINPUTVIEW


var UserInputView = function () {
	function UserInputView(controller) {
		_classCallCheck(this, UserInputView);

		this.controller = controller;
		this.template = null;
		this.html = null;
		this.model = null;
		this.split_view = null;
		this.callbacks = {};
	}

	_createClass(UserInputView, [{
		key: 'createWrapper',
		value: function createWrapper() {
			var wrap = document.createElement('fieldset');
			wrap.classList.add('flex-form__module');
			wrap.setAttribute('id', this.controller.name);
			return wrap;
		}
	}, {
		key: 'setupModel',
		value: function setupModel(model) {

			if (!this.model) {
				this.model = model;
			} else {
				for (var prop in model) {
					this.model[prop] = model[prop];
				}
			}
		}
	}, {
		key: 'render',
		value: function render() {
			var html = this.template(this.model);
			var wrap = this.createWrapper();
			wrap.innerHTML = html;
			this.html = wrap;
			return wrap;
		}
	}, {
		key: 'runCallbacks',
		value: function runCallbacks() {
			var self = this;
			for (var cb in this.callbacks) {
				if (this.callbacks instanceof Function) this.callbacks[cb].call(this.html, this.controller);
				if (this.callbacks instanceof Array) {
					this.callbacks[cb].forEach(function (callback) {
						if (typeof callback === 'function') callback.call(self.html, self.controller);
					});
				}
			}
		}
	}, {
		key: 'afterRender',
		value: function afterRender(cb) {
			if (!cb) return;
			this.callbacks.afterRender = cb;
		}
	}]);

	return UserInputView;
}();

// USERINPUTCONTROLLER


var UserInputController = function () {
	function UserInputController(config) {
		_classCallCheck(this, UserInputController);

		if (!config) config = {};

		this.config = config;
		this.view = new UserInputView(this);
		this.name = config.name || '';
		this.title = config.title || '';
		this.value = config.value || '';
		this.type = config.type || '';
		this.form = config.form || '';
		this.default = config.default || '';
		this.units = config.units || '';

		this.events = {
			change: [],
			render: [],
			init: []
		};

		if (config.on) {
			for (var prop in config.on) {
				this.on(prop, config.on[prop]);
			}
		}

		// assign default value to value if defined
		if (this.default.length) {
			this.value = this.default;
		}

		this.view.setupModel({
			name: this.name,
			title: this.title,
			controller: this
		});
	}

	_createClass(UserInputController, [{
		key: 'setValue',
		value: function setValue(val, cb) {
			this.value = val;
			this.trigger('change', this.value);
			if (cb) cb();
		}
	}, {
		key: 'getValue',
		value: function getValue() {
			return this.value;
		}
	}, {
		key: 'on',
		value: function on(event, fn) {

			if (!this.events.hasOwnProperty(event) || !fn) return;
			this.events[event].push(fn);

			return this;
		}
	}, {
		key: 'trigger',
		value: function trigger(event, data) {
			var self = this;
			if (!this.events.hasOwnProperty(event)) return;
			this.events[event].forEach(function (fn) {
				fn.call(self, data);
			});

			return this;
		}
	}]);

	return UserInputController;
}();

// SIMPLESELECT CONSTRUCTOR (EXTENDS USERINPUTCONTROLLER)


var SimpleSelect = function (_UserInputController) {
	_inherits(SimpleSelect, _UserInputController);

	function SimpleSelect(config) {
		_classCallCheck(this, SimpleSelect);

		var _this = _possibleConstructorReturn(this, (SimpleSelect.__proto__ || Object.getPrototypeOf(SimpleSelect)).call(this, config));

		_this.options = config.options;

		_this.initialise();
		return _this;
	}

	_createClass(SimpleSelect, [{
		key: 'initialise',
		value: function initialise() {

			var self = this;
			this.view.template = TEMPLATES.SimpleSelect;

			this.view.setupModel({
				options: this.options,
				doc_link: this.config.doc_link
			});

			if (this.default) {
				this.options.forEach(function (opt) {
					if (opt.value == self.default) {
						opt.selected = true;
						self.setValue(self.default);
					}
				});
			}

			this.view.afterRender(function (controller) {
				$(this).find('select').bind('change', function () {
					controller.setValue(this.value);
				});
			});
		}
	}]);

	return SimpleSelect;
}(UserInputController);

// TOPSELECT CONSTRUCTOR (EXTENDS USERINPUTCONTROLLER)


var TopSelect = function (_UserInputController2) {
	_inherits(TopSelect, _UserInputController2);

	function TopSelect(config) {
		_classCallCheck(this, TopSelect);

		if (!config) config = {};

		var _this2 = _possibleConstructorReturn(this, (TopSelect.__proto__ || Object.getPrototypeOf(TopSelect)).call(this, config));

		_this2.options = _this2.config.options;
		_this2.extra_select = _this2.config.extra_select;
		_this2.units = _this2.config.units;

		_this2.initialise();
		return _this2;
	}

	_createClass(TopSelect, [{
		key: 'initialise',
		value: function initialise() {

			var self = this;
			var extra = this.extra_select;
			var totalItems = this.options.length;
			var top_items = [];
			var rest_items = [];

			var snapped = false;

			if (totalItems >= 5) {
				top_items = this.options.slice(0, 5);
				rest_items = this.options.slice(5, totalItems);
			} else {
				top_items = this.options;
			}

			if (this.default) {

				this.options.forEach(function (opt) {

					if (opt.value == self.default) {
						opt.selected = true;
						self.setValue(self.default);
						snapped = true;
					}
				});

				if (!snapped) {
					self.setValue(self.default);
					$(self.view.html).find('.manual-input > input').val(self.getValue());
				}
			}

			// controller configures the view
			this.view.template = TEMPLATES.TopSelect;

			// implement a new method on the view which will deselect radio's
			this.view.deselectRadios = function () {
				$(this.html).find('input:radio').prop('checked', false);
			};

			this.view.unsetCustom = function () {
				$(this.html).find('.manual-input').removeClass('active');
				$(this.html).find('.manual-input > input').val('');
			};

			// implement a new method on the view which will reset the selectbox
			this.view.resetOtherSelect = function () {
				$(this.html).find('select[name="' + this.controller.name + '-other"] option:first-child').prop('selected', true);
			};

			this.view.resetAlternateSelect = function () {
				if (!extra) return;
				$(this.html).find('select#' + extra.name + ' option:first-child').prop('selected', true);
			};

			// create model on view
			this.view.setupModel({
				top_items: top_items,
				rest_items: rest_items,
				extra_select: this.config.extra_select,
				doc_link: this.config.doc_link,
				snapped: snapped
			});

			// hook up interaction things
			this.view.afterRender(function (controller) {

				// this = html	
				// controller = interface base controller

				$(this).find('input:radio').bind('change', function (e) {
					controller.setValue(this.value);
					self.view.resetOtherSelect();
					self.view.resetAlternateSelect();
					self.view.unsetCustom();
				});

				$(this).find('select[name="' + controller.name + '-other"]').bind('change', function (e) {
					controller.setValue(this.value);
					self.view.deselectRadios();
					self.view.resetAlternateSelect();
					self.view.unsetCustom();
				});

				$(this).find('.manual-input > input').bind('keyup', function (e) {
					controller.setValue(this.value);
					$(this).parent().addClass('active');
					self.view.deselectRadios();
					self.view.resetAlternateSelect();
				});

				if (!snapped) {
					$(this).find('.manual-input').addClass('active');
					$(this).find('.manual-input > input').val(self.value);
				}

				// to make the extra input a SEPERATE function,
				// we create a new input controller - without the view -
				// we already have the view. we just need the controller.
				if (extra) {

					var inp = new UserInputController({
						name: extra.name,
						title: extra.title,
						on: extra.on || {}
					});

					if (extra.default) {

						extra.options.forEach(function (opt) {
							if (opt.value == extra.default) {
								opt.selected = true;
								inp.setValue(extra.default);
							}
						});
					}

					if (controller.form) controller.form.add(inp);

					$(controller.view.html).find('select#' + extra.name).bind('change', function (e) {
						inp.setValue($(this).val());
						self.view.deselectRadios();
						self.view.resetOtherSelect();
					});
				}
			});
		}
	}, {
		key: 'getValue',
		value: function getValue() {
			return this.value;
		}
	}]);

	return TopSelect;
}(UserInputController);

// TOGGLE LIST with support for EXTRA USER INPUT


var ToggleList = function (_UserInputController3) {
	_inherits(ToggleList, _UserInputController3);

	function ToggleList(config) {
		_classCallCheck(this, ToggleList);

		var _this3 = _possibleConstructorReturn(this, (ToggleList.__proto__ || Object.getPrototypeOf(ToggleList)).call(this, config));

		_this3.initialised = false;
		_this3.options = config.options;
		_this3.config = config;
		_this3.value = {};
		_this3.custom_options = config.custom_options || {};
		_this3.options_extra_predefined = config.options_extra_predefined || [];

		_this3.events = $.extend(_this3.events, {
			remove: []
		});

		if (_this3.default) {
			var self = _this3;

			_this3.options = _this3.options.map(function (option) {
				option.selected = false;
				if (self.default[option.name] === true) {
					option.selected = true;
				}
				return option;
			});
		}

		_this3.initialise();
		return _this3;
	}

	_createClass(ToggleList, [{
		key: 'initialise',
		value: function initialise() {

			var self = this;
			this.view.template = TEMPLATES.ToggleList;

			this.view.setupModel({
				options: this.options,
				extraOptions: this.config.extraOptions,
				doc_link: this.config.doc_link
			});

			for (var opt in this.options) {
				this.value[this.options[opt].name] = this.options[opt].selected || false;
			}

			this.trigger('init');

			this.view.afterRender(function () {

				$(this).find('input:checkbox').bind('change', function (e) {
					self.onToggleChange.call(this, e, self);
				}).each(function () {
					self.onToggleChange.call(this, null, self);
				});

				if (self.config.extraOptions) {
					self.initialiseExtraOptions();
				}

				self.initialised = true;
			});

			return this;
		}
	}, {
		key: 'setOption',
		value: function setOption(name, val) {
			this.value[name] = val;

			if (this.initialised) {
				this.trigger('change', this.getValue());
			}
		}
	}, {
		key: 'onToggleChange',
		value: function onToggleChange(e, self) {
			var $checkbox = $(this);
			var optName = $checkbox.data('option');
			self.setOption(optName, $checkbox.is(':checked'));
		}
	}, {
		key: 'initialiseExtraOptions',
		value: function initialiseExtraOptions() {

			var self = this;

			var $newOptionName = $(this.view.html).find('table tfoot input[name=new-key]');
			var $newOptionValue = $(this.view.html).find('table tfoot input[name=new-value]');

			$(this.view.html).find('table tfoot input[name=new-key], table tfoot input[name=new-value]').bind('keydown', function (e) {

				var optName = $newOptionName.val();
				var optValue = $newOptionValue.val();

				switch (e.keyCode) {
					case 13:
						self.commit(optName, optValue);
						break;
				}
			});

			if (this.options_extra_predefined.length) {
				this.options_extra_predefined.forEach(function (item) {
					self.commit(item.key, item.value);
				});
			}
		}
	}, {
		key: 'removeTableRow',
		value: function removeTableRow(key) {
			$(this.view.html).find('tr[data-option="' + key + '"]').remove();
		}
	}, {
		key: 'createTableRow',
		value: function createTableRow(key, value) {

			var $row = document.createElement('tr');
			var $key = document.createElement('td');
			var $val = document.createElement('td');
			var $remove = document.createElement('a');
			var $icon = document.createElement('i');

			$remove.classList.add('remove');
			$icon.classList.add('fa');
			$icon.classList.add('fa-remove');

			$remove.appendChild($icon);

			$key.innerHTML = key;
			$val.innerHTML = value;
			$val.appendChild($remove);
			$row.appendChild($key);
			$row.appendChild($val);

			$key.classList.add('key');
			$val.classList.add('value');

			$row.setAttribute('data-option', key);

			return $row;
		}
	}, {
		key: 'commit',
		value: function commit(key, value) {

			var self = this;

			var $newOptionName = $(this.view.html).find('table tfoot input[name=new-key]');
			var $newOptionValue = $(this.view.html).find('table tfoot input[name=new-value]');

			if (this.custom_options.hasOwnProperty(key)) return false;
			if (!key || !value) return false;

			this.custom_options[key] = value;

			var el = this.createTableRow(key, value);
			$(this.view.html).find('table tbody').append(el);

			$(el).find('.remove').bind('click', function (e) {
				e.preventDefault();
				self.remove($(this).parents('tr').data('option'));
				self.trigger('remove', self.getValue());
			});

			// resets and focusses back the input fields
			$newOptionName.val('');
			$newOptionValue.val('');
			$newOptionName.focus();

			this.trigger('change', this.getValue());
		}
	}, {
		key: 'remove',
		value: function remove(key) {
			if (this.custom_options.hasOwnProperty(key)) {
				delete this.custom_options[key];
				this.removeTableRow(key);
			}
		}
	}, {
		key: 'getValue',
		value: function getValue() {

			var list = {};

			for (var opt in this.value) {
				list[opt] = this.value[opt];
			}

			if (this.config.extraOptions) {
				for (var o in this.custom_options) {
					list[o] = this.custom_options[o];
				}
			}

			return list;
		}
	}]);

	return ToggleList;
}(UserInputController);

// FORM CONSTRUCTOR


var Form = function () {
	function Form(config) {
		_classCallCheck(this, Form);

		this.config = config;
		this.fields = {};
		this.container = this.config.container || null;

		this.events = {
			change: [],
			render: []
		};

		this.config.configure.call({
			TopSelect: TopSelect,
			SimpleSelect: SimpleSelect,
			Split: Split,
			ToggleList: ToggleList
		}, this);
	}

	_createClass(Form, [{
		key: 'on',
		value: function on(event, fn) {
			if (!this.events.hasOwnProperty(event) || !fn) return;
			this.events[event].push(fn);
			return this;
		}
	}, {
		key: 'trigger',
		value: function trigger(event, data) {

			var self = this;

			if (!this.events.hasOwnProperty(event)) return;
			this.events[event].forEach(function (fn) {
				fn.call(self, data);
			});

			return this;
		}
	}, {
		key: 'add',
		value: function add(element) {

			var self = this;

			if (element instanceof Array) {
				element.forEach(function (item) {
					if (item instanceof Array) {
						var s = new Split(item);
						self.add(s);
					} else {
						self.add(item);
					}
				});
			} else {
				if (element instanceof UserInputController || element instanceof Split) {
					this.fields[element.name] = element;
					this.fields[element.name].form = this;

					// this hooks a callback listener to a change event 
					// from an included field. if it triggers, it will trigger
					// the form 'change' event. 
					element.on('change', function () {
						self.trigger('change', self.serialize());
					});
				} else {
					console.error('Only elements from instance UserInputController and Split are allowed!');
				}
			}
		}
	}, {
		key: 'draw',
		value: function draw() {

			for (var f in this.fields) {
				var field = this.fields[f];

				if (field instanceof UserInputController) {

					field.view.html = field.view.render();
					this.container.appendChild(field.view.html);
					if (field.view.callbacks.afterRender) field.view.callbacks.afterRender.call(field.view.html, field);
				} else if (field instanceof Split) {
					this.container.appendChild(field.draw());

					for (var el in field.elements) {
						var f = field.elements[el];
						if (f.view.callbacks.afterRender) {
							f.view.callbacks.afterRender.call(f.view.html, f);
						}
					}
				}
			}
		}
	}, {
		key: 'serialize',
		value: function serialize() {
			var ret = {};

			function setValue(key, value) {
				ret[key] = value;
			}

			for (var f in this.fields) {
				var field = this.fields[f];
				if (typeof field.getValue === 'function') {
					setValue(field.name, field.getValue());
				}
				if (field instanceof Split) {
					field.elements.forEach(function (el) {
						if (typeof el.getValue === 'function') setValue(el.name, el.getValue());
					});
				}
			}

			return ret;
		}
	}]);

	return Form;
}();

exports.SimpleSelect = SimpleSelect;
exports.TopSelect = TopSelect;
exports.Split = Split;
exports.ToggleList = ToggleList;
exports.Form = Form;

},{}],5:[function(require,module,exports){
'use strict';

Object.defineProperty(exports, "__esModule", {
	value: true
});

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

var SubmissionTaskTable = function () {
	function SubmissionTaskTable(options) {
		_classCallCheck(this, SubmissionTaskTable);

		var self = this;

		this.el = options.el;
		this.task_ids = options.task_ids;
		this.interval = null;
		this.refreshRate = options.refreshRate ? options.refreshRate : 1000; // ms
		this.debug = options.debug;
		this.request_pending = false;
		this.onRender = options.onRender ? options.onRender : function () {};

		// debug
		this.stopIntervalling = 1;
		this.curInterval = 0;

		if (this.task_ids.length) {
			this.interval = setInterval(function () {
				self._status();
				self.curInterval += 1;

				// debug
				if (self.debug && self.curInterval == self.stopIntervalling) {
					self._clear();
				}
			}, this.refreshRate);

			self._status();
		}
	}

	// does a status check


	_createClass(SubmissionTaskTable, [{
		key: '_status',
		value: function _status(callback) {

			var self = this;

			// this blocks out making requests if we are already doing a request.
			// this makes every request 'wait' untill all requests did finish.
			if (this.request_pending) return;
			this.request_pending = true;

			this.setStatusText('Getting status...');

			CuckooWeb.api_post('/analysis/api/tasks/info/', {
				"task_ids": self.task_ids
			}, function (response) {
				self._data(response);
				self.request_pending = false;
			}, function (err) {
				self._clear();
				self.setStatusText('There was an error!');
			});
		}

		// processes the data

	}, {
		key: '_data',
		value: function _data(response) {

			this.setStatusText('Done');

			var data = response.data;

			// building the check, but it's always an object,
			// so do some array formatting here, while keeping
			// the correct order.
			if (!(data instanceof Array)) {
				var arr = [];
				for (var d in response.data) {
					arr.push(response.data[d]);
				}
				data = arr.sort(function (a, b) {
					return a.id > b.id;
				});
			}

			// humanize the date formats, or any other kind of data
			data = data.map(function (item) {
				item.date_added = moment(item.added_on).format('DD/MM/YYYY');
				item.time_added = moment(item.added_on).format('HH:mm');
				item.is_ready = item.status == 'reported';
				item.is_running = item.status == 'running';
				item.remote_control = item.options.hasOwnProperty('remotecontrol');
				item.show_rc_toggle = item.remote_control && item.is_running;
				return item;
			});

			this._draw(data);
		}

		// draws the table content from Handlebars into the table

	}, {
		key: '_draw',
		value: function _draw(data) {
			var template = HANDLEBARS_TEMPLATES['submission-task-table-body'];
			$(this.el).find('tbody').html(template({ tasks: data }));
			this.onRender($(this.el));
		}

		// clears the interval

	}, {
		key: '_clear',
		value: function _clear() {
			if (this.interval) clearInterval(this.interval);
			this.request_pending = false;
		}
	}, {
		key: 'setStatusText',
		value: function setStatusText(text) {
			$(this.el).find('tfoot .ajax-status').text(text);
		}
	}]);

	return SubmissionTaskTable;
}();

exports.SubmissionTaskTable = SubmissionTaskTable;

},{}],6:[function(require,module,exports){
'use strict';

var _InterfaceControllers = require('./components/InterfaceControllers');

var InterfaceControllers = _interopRequireWildcard(_InterfaceControllers);

var _FileTree = require('./components/FileTree');

var FileTree = _interopRequireWildcard(_FileTree);

var _Analysis = require('./components/Analysis');

var Analysis = _interopRequireWildcard(_Analysis);

var _SubmissionTaskTable = require('./components/SubmissionTaskTable');

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) newObj[key] = obj[key]; } } newObj.default = obj; return newObj; } }

// default values for the analysis options
var default_analysis_options = {
	'machine': 'default',
	'network-routing': 'internet',
	'options': {
		'enforce-timeout': false,
		'full-memory-dump': false,
		'enable-injection': true,
		'process-memory-dump': true,
		'simulated-human-interaction': true,
		'remote-control': false
	},
	'package': null,
	'priority': 1,
	'timeout': 120,
	'vpn': 'united-states',
	'available_vpns': [],
	'available_machines': []

	// default option set for the submission form
};var submission_options = [{
	name: 'remote-control',
	label: 'Remote Control',
	description: 'Enables Guacamole UI for VM'
}, {
	name: 'enable-injection',
	label: 'Enable Injection',
	description: 'Enable behavioral analysis.'
}, {
	name: 'process-memory-dump',
	label: 'Process Memory Dump'
}, {
	name: 'full-memory-dump',
	label: 'Full Memory Dump',
	description: 'If Volatility has been enabled, process an entire VM memory dump with it.'
}, {
	name: 'enforce-timeout',
	label: 'Enforce Timeout'
}, {
	name: 'simulated-human-interaction',
	label: 'Enable Simulated Human Interaction',
	selected: true,
	description: 'disable this feature for a better experience when using Remote Control',
	showWhen: {
		'remote-control': true
	}
}];

// package field contents - hardcoded options vs auto-detected properties
// gets updated when packages come back that aren;t in this array in the response
// serialization code.
var default_package_selection_options = ['default', 'com', 'cpl', 'dll', 'doc', 'exe', 'generic', 'ie', 'ff', 'jar', 'js', 'jse', 'hta', 'hwp', 'msi', 'pdf', 'ppt', 'ps1', 'pub', 'python', 'vbs', 'wsf', 'xls', 'zip'];
var routing_prefs = {};

// appends a helper to handlebars for humanizing sizes
Handlebars.registerHelper('file_size', function (text) {
	return new Handlebars.SafeString(FileTree.humanizeBytes(parseInt(text)));
});

$(function () {

	var debugging = window.location.toString().indexOf('#debugging') !== -1;

	if (debugging) {
		console.debug('You run this module in debug mode. to disable it, remove #debugging from the url.');
		console.debug('Clicking analyze will output the JSON results to the console.');
		console.debug('Submitting is unavailable in this mode.');
		$('.flex-grid__footer').css('display', 'none');
	}

	if (document.getElementById('analysis-configuration') !== null) {

		// collects the entire ui of this page
		var analysis_ui = new Analysis.AnalysisInterface({
			container: document.getElementById('analysis-configuration'),
			// specifies the file tree configuration
			filetree: {
				config: {
					label: 'filetree',
					autoExpand: true,
					sidebar: document.getElementById('filetree-detail'),
					nameKey: 'filename', // name of the file name property
					isDirectory: function isDirectory(item) {
						return item.type === 'directory' || item.type === 'container';
					}
				},
				load: {
					url: '/submit/api/filetree',
					method: 'POST',
					params: {
						"submit_id": window.submit_id
					},
					error: function error(err) {

						var $ftErr = $('<div class="filetree-error">\n\t\t\t\t\t\t\t<div class="cross">\n\t\t\t\t\t\t\t\t<span class="cross-line"></span>\n\t\t\t\t\t\t\t\t<span class="cross-line"></span>\n\t\t\t\t\t\t\t</div>\n\t\t\t\t\t\t\t<p class="error-message">Something went wrong.</p>\n\t\t\t\t\t\t</div>');

						$(this.el).html($ftErr);
						setTimeout(function () {
							$ftErr.addClass('in');
						}, 500);

						// $(this.el).html(`<div class="filetree-error">
						// 	<div class="cross">
						// 		<span class="cross-line"></span>
						// 		<span class="cross-line"></span>
						// 	</div>
						// 	<p class="error-message">Something went wrong.</p>
						// </div>`);
					},
					serialize: function serialize(response) {

						// set up defaults for form and settings
						if (response.defaults) {
							default_analysis_options = response.defaults;

							// extract the routing settings and delete
							routing_prefs = default_analysis_options.routing;
							default_analysis_options.routing = routing_prefs.route;

							// format the vpns array to work for the form field, using a 'name-value']
							default_analysis_options.available_vpns = routing_prefs.vpns.map(function (vpn) {
								return {
									name: vpn,
									value: vpn
								};
							});

							// if we have 'null' for machines, force it to be mappable by replacing
							// it with an empty array instead.
							if (!default_analysis_options.machine) {
								default_analysis_options.machine = new Array();
							}

							// parse the available machines
							default_analysis_options.available_machines = default_analysis_options.machine.map(function (machine) {
								return {
									name: machine,
									value: machine
								};
							});

							// create a 'default=null' value
							default_analysis_options.available_machines.unshift({
								name: 'default',
								value: null
							});

							// set the value to 'default' (or null in this case)
							default_analysis_options.machine = default_analysis_options.available_machines[0].value;
						}

						analysis_ui.originalData = response.files;

						FileTree.FileTree.iterateFileStructure(response.files, function (item) {

							item.per_file_options = $.extend(new Object(), default_analysis_options);
							item.changed_properties = [];

							// machine guess: package options
							// - also preselects the package field if available

							if (item.package) {
								item.per_file_options['package'] = item.package;
								if (default_package_selection_options.indexOf(item.package) == -1) {
									default_package_selection_options.push(item.package);
								}
								item.changed_properties.push('package');
							}

							var parentContainer = FileTree.FileTree.getParentContainerName(item);
							if (parentContainer) item.arcname = parentContainer.filename;
						});

						default_package_selection_options = default_package_selection_options.map(function (opt) {
							return {
								name: opt,
								value: opt
							};
						});

						return response.files;
					}
				},
				transform: {
					file: function file(el, controller) {

						var self = this;

						// this = item
						var _$d = $(el).find('div');
						var size = FileTree.Label('size', FileTree.humanizeBytes(this.size));
						var info = FileTree.Label('info', '<i class="fa fa-info-circle"></i>', 'a');

						// adds the meta data
						_$d.append(info, size);

						if (this.duplicate) {
							var duplicate = FileTree.Label('duplicate', 'duplicate file');
							_$d.append(duplicate);
						}

						$(info).on('click', function (e) {
							e.stopImmediatePropagation();
							controller.detailView(self);
						});

						// make sure the filename is escaped to prevent XSS attacks
						this.filename = CuckooWeb.escapeHTML(this.filename);

						return el;
					},

					folder: function folder(el, controller) {

						var self = this;
						var _$d = $(el).find('div');
						var size = FileTree.Label('size', FileTree.humanizeBytes(FileTree.folderSize(this)));
						var archive, info;

						if (this.type === 'container') {
							_$d.addClass('archive-container');
						}

						_$d.append(size);

						if (!this.preview) {
							// _$d.find('strong').addClass('skip-auto-expand');
							_$d.parent().addClass('skip-auto-expand');
							archive = FileTree.Label('archive', 'Archive');

							if (this.type !== 'directory') {
								info = FileTree.Label('info', '<i class="fa fa-info-circle"></i>', 'a');
								_$d.prepend(info);

								// makes info circle clickable
								$(info).on('click', function (e) {
									e.stopImmediatePropagation();
									controller.detailView(self);
								});
							}
							_$d.append(archive);
						}

						return el;
					}
				},
				after: {
					selectionView: function selectionView() {},
					detailView: function detailView(el, filetree) {

						var item = this;
						var $per_file_options = $(el).find('.per-file-options')[0];

						if ($per_file_options) {

							// sets a value on a field
							var setFieldValue = function setFieldValue(value) {

								var field = fieldName(this.name);

								if (item.changed_properties.indexOf(field) == -1) {
									item.changed_properties.push(field);
								}

								item.per_file_options[field] = value;
							};

							// returns the fieldname as is


							var fieldName = function fieldName(str) {
								var spl = str.split('-');
								spl.splice(-1, 1);
								return spl.join('-');
							};

							var form = new InterfaceControllers.Form({
								container: $per_file_options,
								configure: function configure(form) {

									var network = new this.TopSelect({
										name: 'network-routing-' + item.filetree.index,
										title: 'Network Routing',
										doc_link: 'https://cuckoo.sh/docs/installation/host/routing.html',
										default: item.per_file_options['network-routing'],
										options: [{ name: 'none', value: 'none', disabled: routing_prefs['none'] === false }, { name: 'drop', value: 'drop', disabled: routing_prefs['drop'] === false }, { name: 'internet', value: 'internet', disabled: routing_prefs['internet'] === false }, { name: 'inetsim', value: 'inetsim', disabled: routing_prefs['inetsim'] === false }, { name: 'tor', value: 'tor', disabled: routing_prefs['tor'] === false }],
										extra_select: {
											title: 'VPN via',
											name: 'vpn-' + item.filetree.index,
											default: item.per_file_options['vpn'] || undefined,
											disabled: routing_prefs['vpn'] === false || default_analysis_options.available_vpns.length === 0,
											options: default_analysis_options.available_vpns
										}
									}).on('change', function (value) {
										item.per_file_options['network-routing'] = value;
										setFieldValue.call(this, value);
									});

									var pkg = new this.SimpleSelect({
										name: 'package-' + item.filetree.index,
										title: 'Package',
										doc_link: 'https://cuckoo.sh/docs/usage/packages.html',
										default: item.per_file_options['package'],
										options: default_package_selection_options
									}).on('change', function (value) {

										item.per_file_options['package'] = value;
										if (value == 'default') value = null;
										setFieldValue.call(this, value);
									});

									var priority = new this.TopSelect({
										name: 'piority-' + item.filetree.index,
										title: 'Priority',
										default: parseInt(item.per_file_options['priority']),
										options: [{ name: 'low', value: 1, className: 'priority-s' }, { name: 'medium', value: 2, className: 'priority-m' }, { name: 'high', value: 3, className: 'priority-l' }]
									}).on('change', function (value) {
										item.per_file_options['priority'] = value;
										setFieldValue.call(this, parseInt(value));
									});

									var timeout = new this.TopSelect({
										name: 'timeout-' + item.filetree.index,
										title: 'Timeout',
										default: item.per_file_options['timeout'],
										units: 'seconds',
										options: [{ name: 'short', value: 60, description: '60' }, { name: 'medium', value: 120, description: '120' }, { name: 'long', value: 300, description: '300' }, { name: 'custom', manual: true }]
									}).on('change', function (value) {
										item.per_file_options['timeout'] = value;
										setFieldValue.call(this, value);
									});

									var config = new this.ToggleList({
										name: 'options-' + item.filetree.index,
										title: 'Options',
										extraOptions: true,
										default: item.per_file_options['options'],
										options: submission_options,
										on: {
											init: function init() {

												/*
            	attach any predefined values to the stack
             */

												var custom = [];

												var default_options = this.options.map(function (item) {
													return item.name;
												});

												for (var default_option in this.default) {
													if (default_options.indexOf(default_option) == -1) {
														custom.push({
															key: default_option,
															value: this.default[default_option]
														});
													}
												}

												this.options_extra_predefined = custom;
											},
											change: function change(value) {
												item.per_file_options['options'] = value;
												setFieldValue.call(this, value);
											}
										}
									});

									var machine = new this.SimpleSelect({
										name: 'machine-' + item.filetree.index,
										title: 'Machine',
										default: item.per_file_options['machine'],
										options: default_analysis_options.available_machines
									}).on('change', function (value) {
										item.per_file_options['machine'] = value;
										setFieldValue.call(this, value);
									});

									form.add([network, [pkg, priority], timeout, config, machine]);

									form.draw();
								}
							});
						}
					}
				}
			},

			// specifies the form configuration
			form: {
				container: document.getElementById('submission-config'),
				configure: function configure(form) {

					// this configuration allows for dynamic (yes, dynamic) forms

					var network = new this.TopSelect({
						name: 'network-routing',
						title: 'Network Routing',
						default: default_analysis_options['routing'],
						doc_link: 'https://cuckoo.sh/docs/installation/host/routing.html',
						options: [{ name: 'none', value: 'none', disabled: routing_prefs['none'] === false }, { name: 'drop', value: 'drop', disabled: routing_prefs['drop'] === false }, { name: 'internet', value: 'internet', disabled: routing_prefs['internet'] === false }, { name: 'inetsim', value: 'inetsim', disabled: routing_prefs['inetsim'] === false }, { name: 'tor', value: 'tor', disabled: routing_prefs['tor'] === false }],
						extra_select: {
							title: 'VPN via',
							name: 'vpn',
							disabled: routing_prefs['vpn'] === false || default_analysis_options.available_vpns.length === 0,
							on: {
								change: function change() {
									// console.log('vpn changed');
								}
							},
							options: default_analysis_options.available_vpns
						}
					});

					var pkg = new this.SimpleSelect({
						name: 'package',
						title: 'Package',
						doc_link: 'https://cuckoo.sh/docs/usage/packages.html',
						default: default_analysis_options['package'],
						options: default_package_selection_options
					}).on('change', function (value) {

						// sets all items to the correct value of package, this does
						// not seem to work correctly, so this basically forces the
						// correct value.
						analysis_ui.filetree.each(function (item) {
							item.per_file_options.package = value;
						});
					});

					var priority = new this.TopSelect({
						name: 'priority',
						title: 'Priority',
						default: default_analysis_options['priority'],
						options: [{ name: 'low', value: 1, className: 'priority-s' }, { name: 'medium', value: 2, className: 'priority-m' }, { name: 'high', value: 3, className: 'priority-l' }]
					});

					var config = new this.ToggleList({
						name: 'options',
						title: 'Options',
						default: default_analysis_options['options'],
						extraOptions: true,
						options: submission_options
					});

					var machine = new this.SimpleSelect({
						name: 'machine',
						title: 'Machine',
						default: default_analysis_options['machine'],
						options: default_analysis_options['available_machines']
					});

					var timeout = new this.TopSelect({
						name: 'timeout',
						title: 'Timeout',
						default: default_analysis_options['timeout'],
						units: 'seconds',
						options: [{ name: 'short', value: 60, description: '60' }, { name: 'medium', value: 120, description: '120' }, { name: 'long', value: 300, description: '300' }, { name: 'custom', manual: true }]
					});

					// an array inside this array will render the elements in a split view
					form.add([network, [pkg, priority], timeout, config, machine]);
					form.draw();

					// this gets fired EVERY time one of the fields
					// insdie the form gets updated. it sends
					// back an object with all the current values of
					// the form instance.
					form.on('change', function (values) {

						function compareAndOverwrite(item) {

							// makes only exception rule for 'package'
							for (var val in values) {
								if (item.changed_properties && item.changed_properties.indexOf(val) == -1 && val !== 'package') {
									item.per_file_options[val] = values[val];
								}
							}
						}

						analysis_ui.filetree.each(function (item) {
							compareAndOverwrite(item);
						});

						// update any active detail views, respecting custom presets made
						// by the user. Actually 're-render' the current detail view to persist
						// default settings 'asynchonously' - as you would expect.
						if (analysis_ui.filetree.detailViewActive) {
							var active_index = analysis_ui.filetree.activeIndex;
							analysis_ui.filetree.detailView(analysis_ui.filetree.getIndex(active_index));
						}
					});
				}
			},
			// base configuration for the dnd uploader
			dndupload: {
				endpoint: '/submit/api/presubmit',
				target: 'div#dndsubmit',
				template: HANDLEBARS_TEMPLATES['dndupload'],
				success: function success(data, holder) {

					$(holder).removeClass('dropped');
					$(holder).addClass('done');

					// fake timeout
					setTimeout(function () {
						window.location.href = data.responseURL;
					}, 1000);
				},
				error: function error(uploader, holder) {
					$(holder).addClass('error');
				},
				progress: function progress(value, holder) {
					// thisArg is bound to the uploader
					if (value > 50 && !$(holder).hasClass('progress-half')) {
						$(holder).addClass('progress-half');
					}

					$(this.options.target).find(".alternate-progress").css('transform', 'translateY(' + (100 - value) + '%)');
				},
				dragstart: function dragstart(uploader, holder) {
					holder.classList.add('hover');
				},
				dragend: function dragend(uploader, holder) {
					holder.classList.remove('hover');
				},
				drop: function drop(uploader, holder) {
					holder.classList.remove('hover');
					holder.classList.add('dropped');
				}
			}
		});

		$('#start-analysis').bind('click', function (e) {

			e.preventDefault();

			var data = JSON.parse(analysis_ui.getData({
				'submit_id': window.submit_id
			}, true));

			if (!data.file_selection.length) {
				alert('Please select some files first.');
				return;
			}

			// $(".page-freeze").addClass('in');
			CuckooWeb.toggle_page_freeze(true, "We're processing your submission... This could take a few seconds.");

			if (debugging) {
				console.log(data);
				return;
			}

			CuckooWeb.api_post('/submit/api/submit', data, function (data) {
				if (data.status === true) {
					// redirect to submission success page
					window.location = '/submit/post/' + data.submit_id;
				} else {
					// alert("Submission failed: " + data.message);
					CuckooWeb.error_page_freeze("Something went wrong! please try again.");
				}
			}, function () {
				console.log(arguments);
				// alert('submission failed! see the console for details.');
				CuckooWeb.error_page_freeze("Something went wrong! please try again.");
			});
		});

		$("#reset-options").bind('click', function (e) {
			e.preventDefault();
		});

		$(".upload-module .grouped-buttons a").on('shown.bs.tab', function (e) {
			$(e.target).parent().find('a').removeClass('active');
			$(this).addClass('active');
		});

		// taken from the previous submit functionality
		$("input#urlhash").click(function () {

			var urls = $("textarea#presubmit_urlhash").val();
			if (urls == "") {
				return;
			}

			CuckooWeb.api_post("/submit/api/presubmit", {
				"data": urls,
				"type": "strings"
			}, function (data) {
				CuckooWeb.redirect("/submit/pre/" + data.submit_id);
			}, function (data) {
				console.log("err: " + data);
			});
		});
	}

	// submission task summary init
	if (document.getElementById('submission-task-table') !== null) {
		var taskTable = new _SubmissionTaskTable.SubmissionTaskTable({
			el: document.getElementById('submission-task-table'),
			task_ids: task_ids,
			debug: false, // set to true to do 10 calls max and stop
			refreshRate: 2500,
			onRender: function onRender(el) {
				// opens up the task in a new task, if this task has finished processing
				el.find('tbody > tr.finished').bind('click', function () {
					var id = $(this).data('taskId');
					window.open('/analysis/' + id);
				});
			}
		});
	}
});

},{"./components/Analysis":1,"./components/FileTree":3,"./components/InterfaceControllers":4,"./components/SubmissionTaskTable":5}]},{},[6])


//# sourceMappingURL=submission.js.map
