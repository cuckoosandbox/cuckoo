(function e(t,n,r){function s(o,u){if(!n[o]){if(!t[o]){var a=typeof require=="function"&&require;if(!u&&a)return a(o,!0);if(i)return i(o,!0);var f=new Error("Cannot find module '"+o+"'");throw f.code="MODULE_NOT_FOUND",f}var l=n[o]={exports:{}};t[o][0].call(l.exports,function(e){var n=t[o][1][e];return s(n?n:e)},l,l.exports,e,t,n,r)}return n[o].exports}var i=typeof require=="function"&&require;for(var o=0;o<r.length;o++)s(r[o]);return s})({1:[function(require,module,exports){
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

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) newObj[key] = obj[key]; } } newObj.default = obj; return newObj; } }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

var DEFAULT_ANALYSIS_CONFIG = {
	container: null,
	filetree: FileTree.DEFAULT_FILETREE_CONFIG
};

function createFileTree(element, config) {
	var filetree = new FileTree.FileTree(element, config);
	return filetree;
}

var AnalysisInterface = function () {
	function AnalysisInterface(options) {
		_classCallCheck(this, AnalysisInterface);

		this.options = $.extend(true, DEFAULT_ANALYSIS_CONFIG, options);
		this.filetree = createFileTree(this.options.container.querySelector('#filetree'), this.options.filetree);
		this.form = new InterfaceControllers.Form(this.options.form);
	}

	_createClass(AnalysisInterface, [{
		key: 'getData',
		value: function getData() {
			var form_values = this.form.serialize();
			form_values.file_selection = this.filetree.serialize();
			return form_values;
		}
	}]);

	return AnalysisInterface;
}();

exports.AnalysisInterface = AnalysisInterface;

},{"./FileTree":2,"./InterfaceControllers":3}],2:[function(require,module,exports){
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
	return name;
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
			el: null
		};

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

var FileTree = function () {
	function FileTree(el, options) {
		_classCallCheck(this, FileTree);

		this.el = el;
		this.options = options;
		this.data = null;

		this.selectionViewActive = false;
		this.detailViewActive = false;
		this.activeIndex = null;

		// tiny configuration handlers
		this.interactionHandlers = {
			expandAllFolders: function expandAllFolders() {
				$(this.el).find('[data-type="folder"]').parent().addClass('expanded');
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
				this.update();
				this.selectionView();
			},
			showSelection: function showSelection() {
				this.selectionView();
			}
		};

		if (this.options.load.url) this.load(this.options.load.url, this.options.load.params);

		if (this.options.config.autoExpand) this.interactionHandlers.expandAllFolders.call(this);
	}

	_createClass(FileTree, [{
		key: 'initialise',
		value: function initialise(data) {
			this.data = data;
			this.construct();
			if (this.options.events.ready) {
				this.options.events['ready'].call(this);
			}
		}

		// builds the HTML from the data set

	}, {
		key: 'construct',
		value: function construct() {

			itemIndex = 0;
			this.el.innerHTML = '';
			var html = build.call(this, this.data.children, document.createElement('ul'));

			this.el.appendChild(html);

			iterateDOM($(this.el).find('ul:first-child'), 1, function (level) {
				$(this).css('padding-left', level * 10);
			});

			this.connectListeners();
			this.update();
			this.selectionView();
		}

		// binds event (click) listeners

	}, {
		key: 'connectListeners',
		value: function connectListeners() {

			var self = this;

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
			var self = this;

			// response handler
			function handleResponse(response) {
				if (self.options.load.serialize) {
					response = self.options.load.serialize(response);
				}
				self.initialise(response);
			}

			if (!properties) {
				$.get(url).done(handleResponse);
			} else {
				CuckooWeb.api_post("/submit/api/filetree/", properties, handleResponse);
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

			if (item.filetree.is_directory) return;

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

			var selected = this.findByProperty('selected', true);
			var extensions = getExtensions(selected);

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

			console.log(this.options);
			this.options.after.selectionView.call(selected, this.options.config.sidebar, this);
		}
	}, {
		key: 'serialize',
		value: function serialize() {
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
				delete item.filetree;
				return item;
			});
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

exports.FileTree = FileTree;
exports.Label = Label;
exports.humanizeBytes = humanizeBytes;
exports.folderSize = folderSize;
exports.DEFAULT_FILETREE_CONFIG = DEFAULT_FILETREE_CONFIG;

},{}],3:[function(require,module,exports){
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
};

// renders two interface controllers onto one row

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

		this.events = {
			change: [],
			render: []
		};

		// assign default value to value if defined
		if (this.default.length) {
			this.value = this.default;
		}

		this.view.setupModel({
			name: this.name,
			title: this.title
		});
	}

	_createClass(UserInputController, [{
		key: 'setValue',
		value: function setValue(val) {
			this.value = val;
			this.trigger('change', this.value);
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

			this.view.template = TEMPLATES.SimpleSelect;

			this.view.setupModel({
				options: this.options
			});

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

			if (totalItems >= 5) {
				top_items = this.options.slice(0, 5);
				rest_items = this.options.slice(5, totalItems);
			} else {
				top_items = this.options;
			}

			this.options.forEach(function (opt) {
				if (opt.selected) {
					self.setValue(opt.value);
				}
			});

			// controller configures the view
			this.view.template = TEMPLATES.TopSelect;

			// implement a new method on the view which will deselect radio's
			this.view.deselectRadios = function () {
				$(this.html).find('input:radio').prop('checked', false);
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
				extra_select: this.config.extra_select
			});

			// hook up interaction things
			this.view.afterRender(function (controller) {

				// this = html	
				// controller = interface base controller

				$(this).find('input:radio').bind('change', function (e) {
					controller.setValue(this.value);
					self.view.resetOtherSelect();
					self.view.resetAlternateSelect();
				});

				$(this).find('select[name="' + controller.name + '-other"]').bind('change', function (e) {
					controller.setValue(this.value);
					self.view.deselectRadios();
					self.view.resetAlternateSelect();
				});

				// to make the extra input a SEPERATE function,
				// we create a new input controller - without the view -
				// we already have the view. we just need the controller.
				if (extra) {

					var inp = new UserInputController({
						name: extra.name,
						title: extra.title
					});

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

		_this3.options = config.options;
		_this3.config = config;
		_this3.value = {};
		_this3.custom_options = config.custom_options || {};

		_this3.events = $.extend(_this3.events, {
			remove: []
		});

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
				extraOptions: this.config.extraOptions
			});

			for (var opt in this.options) {
				this.value[this.options[opt].name] = this.options[opt].selected || false;
			}

			this.view.afterRender(function () {

				$(this).find('input:checkbox').bind('change', function (e) {
					self.onToggleChange.call(this, e, self);
				}).each(function () {
					self.onToggleChange.call(this, null, self);
				});

				if (self.config.extraOptions) self.initialiseExtraOptions();
			});
		}
	}, {
		key: 'setOption',
		value: function setOption(name, val) {
			this.value[name] = val;
			this.trigger('change', this.getValue());
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

			if (self.config.options_extra_predefined) {
				self.config.options_extra_predefined.forEach(function (item) {
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
						self.trigger('change');
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

},{}],4:[function(require,module,exports){
'use strict';

var _InterfaceControllers = require('./components/InterfaceControllers');

var InterfaceControllers = _interopRequireWildcard(_InterfaceControllers);

var _FileTree = require('./components/FileTree');

var FileTree = _interopRequireWildcard(_FileTree);

var _Analysis = require('./components/Analysis');

var Analysis = _interopRequireWildcard(_Analysis);

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) newObj[key] = obj[key]; } } newObj.default = obj; return newObj; } }

// appends a helper to handlebars for humanizing sizes
Handlebars.registerHelper('file_size', function (text) {
	return new Handlebars.SafeString(FileTree.humanizeBytes(parseInt(text)));
});

$(function () {

	var debugging = false;

	// if(debugging) {
	// 	$('.flex-grid__footer').css('display', 'none');
	// }

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
					serialize: function serialize(response) {
						return response.data.files[0];
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

						$(info).on('click', function (e) {
							e.stopImmediatePropagation();
							controller.detailView(self);
						});

						return el;
					},

					folder: function folder(el, controller) {

						var _$d = $(el).find('div');
						var size = FileTree.Label('size', FileTree.humanizeBytes(FileTree.folderSize(this)));
						_$d.append(size);

						return el;
					}
				},
				after: {
					selectionView: function selectionView() {},
					detailView: function detailView(el, filetree) {

						var item = this;
						var $per_file_options = $(el).find('.per-file-options')[0];

						if ($per_file_options) {

							var form = new InterfaceControllers.Form({
								container: $per_file_options,
								configure: function configure(form) {

									var network = new this.TopSelect({
										name: 'network-routing-' + item.filetree.index,
										title: 'Network Routing',
										options: [{ name: 'none', value: 'none' }, { name: 'drop', value: 'drop' }, { name: 'internet', value: 'internet', selected: true }, { name: 'inetsim', value: 'inetsim' }, { name: 'tor', value: 'tor' }],
										extra_select: {
											title: 'VPN via',
											name: 'vpn-' + item.filetree.index,
											options: [{ name: 'France', value: 'FR-fr' }]
										}
									});

									var pkg = new this.SimpleSelect({
										name: 'package',
										title: 'Package',
										default: 'python',
										options: [{ name: 'Python', value: 'python' }, { name: 'Javascript', value: 'js' }]
									});

									var priority = new this.TopSelect({
										name: 'piority-' + item.filetree.index,
										title: 'Priority',
										options: [{ name: 'low', value: 0, className: 'priority-s' }, { name: 'medium', value: 1, className: 'priority-m' }, { name: 'high', value: 2, className: 'priority-l' }]
									});

									var config = new this.ToggleList({
										name: 'options-' + item.filetree.index,
										title: 'Options',
										extraOptions: true,
										options: [{
											name: 'no-injection',
											label: 'No Injection',
											description: 'Disable behavioral analysis.'
										}, {
											name: 'process-memory-dump',
											label: 'Process Memory Dump',
											selected: true
										}, {
											name: 'full-memory-dump',
											label: 'Full Memory Dump',
											description: 'If the “memory” processing module is enabled, will launch a Volatality Analysis.'
										}, {
											name: 'enforce-timeout',
											label: 'Enforce Timeout'
										}, {
											name: 'simulated-human-interaction',
											label: 'Enable Simulated Human Interaction',
											selected: true
										}, {
											name: 'enable-services',
											label: 'Enable Services',
											description: 'Enable simulated environment specified in the auxiliary configuration.',
											selected: true
										}]
									});

									var machine = new this.SimpleSelect({
										name: 'machine-' + item.filetree.index,
										title: 'Machine',
										default: 'default',
										options: [{ name: 'default', value: 'default' }, { name: 'Cuckoo1', value: 'Cuckoo1' }, { name: 'Cuckoo2', value: 'Cuckoo2' }]
									});

									form.add([network, [pkg, priority], config, machine]);
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
						options: [{ name: 'none', value: 'none' }, { name: 'drop', value: 'drop' }, { name: 'internet', value: 'internet', selected: true }, { name: 'inetsim', value: 'inetsim' }, { name: 'tor', value: 'tor' }],
						extra_select: {
							title: 'VPN via',
							name: 'vpn',
							options: [{ name: 'France', value: 'FR-fr' }]
						}
					});

					var pkg = new this.SimpleSelect({
						name: 'package',
						title: 'Package',
						default: 'python',
						options: [{ name: 'Python', value: 'python' }, { name: 'Javascript', value: 'js' }]
					});

					var priority = new this.TopSelect({
						name: 'piority',
						title: 'Priority',
						options: [{ name: 'low', value: 0, className: 'priority-s' }, { name: 'medium', value: 1, className: 'priority-m' }, { name: 'high', value: 2, className: 'priority-l' }]
					});

					var config = new this.ToggleList({
						name: 'options',
						title: 'Options',
						extraOptions: true,
						options: [{
							name: 'no-injection',
							label: 'No Injection',
							description: 'Disable behavioral analysis.'
						}, {
							name: 'process-memory-dump',
							label: 'Process Memory Dump',
							selected: true
						}, {
							name: 'full-memory-dump',
							label: 'Full Memory Dump',
							description: 'If the “memory” processing module is enabled, will launch a Volatality Analysis.'
						}, {
							name: 'enforce-timeout',
							label: 'Enforce Timeout'
						}, {
							name: 'simulated-human-interaction',
							label: 'Enable Simulated Human Interaction',
							selected: true
						}, {
							name: 'enable-services',
							label: 'Enable Services',
							description: 'Enable simulated environment specified in the auxiliary configuration.',
							selected: true
						}]
					});

					var machine = new this.SimpleSelect({
						name: 'machine',
						title: 'Machine',
						default: 'default',
						options: [{ name: 'default', value: 'default' }, { name: 'Cuckoo1', value: 'Cuckoo1' }, { name: 'Cuckoo2', value: 'Cuckoo2' }]
					});

					// an array inside this array will render the elements in a split view
					form.add([network, [pkg, priority], config, machine]);
					form.draw();

					// this gets fired EVERY time one of the fields
					// insdie the form gets updated. it sends 
					// back an object with all the current values of 
					// the form instance.
					form.on('change', function (data) {
						console.log(data);
					});
				}
			}
		});

		$('#start-analysis').bind('click', function (e) {
			e.preventDefault();
			var json = analysis_ui.getData();
			console.log(json);
		});
	}
});

},{"./components/Analysis":1,"./components/FileTree":2,"./components/InterfaceControllers":3}]},{},[4])


//# sourceMappingURL=submission.js.map
