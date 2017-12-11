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

const DEFAULT_FILETREE_CONFIG = {
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
		isDirectory: function(item) {
			return item.type === 'directory';
		}
	},
	// options for retrieving HTTP data, like files
	load: {
		url: null,
		method: null,
		params: {},
		// function formatting incoming responses from HTTP request - Function (ret ResponseObject)
		serialize: function(response) {
			return response;
		}
	},
	// options for custom formatting of drawn elements
	transform: {
		// function that transform a drawn file element - Function (ret DOM)
		file: function(el, controller) {
			return el;
		},
		// function that transforms a drawn folder element - Function (ret DOM)
		folder: function(el, controller) {
			return el;
		}
	},
	// custom event hooks
	events: {
		// gets fired when clicked on a folder
		folder_click: function(expanded) {},
		// gets fired when clicked on a file
		file_click: function() {},
		// gets fired when selected an item
		select: function(item, selection) {},
		// gets fired when JSON is done loading
		ready: function() {}
	},
	// handlebars templates
	templates: {},
	after: {
		detailView: function() {},
		selectionView: function() {}
	}
}

let itemIndex = 0; // global item index
let detailTemplate = HANDLEBARS_TEMPLATES['submission-file-detail'];
let selectionTemplate = HANDLEBARS_TEMPLATES['submission-selection-list'];

// returns name of the item
function getItemName(item) {
	var name = item.name;
	if(this.options.config.nameKey) {
		name = item[this.options.config.nameKey];
	}
	return CuckooWeb.escapeHTML(name);
}

function createSelectable(item, name, text) {

	var id 	= name + '-' + item.filetree.index;
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
	if(item.duplicate) {
		item.selected = false;
	}

	if(item.selected) {
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
		if(!self.options.config.isDirectory) {
			return item.hasOwnProperty('children');
		} else {
			return self.options.config.isDirectory(item);
		}
	}

	for(var i in items) {

		var item = items[i];
		itemIndex += 1;

		item.filetree = {
			index: itemIndex,
			is_directory: isDirectory(item),
			is_package: false,
			el: null
		};

		if(!item.preview) {
			item.filetree.is_directory = false;
			item.filetree.is_package = true;
		}

		if(isDirectory.call(this, item)) {
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

		if(item.duplicate) {
			item.filetree.el.classList.add('is-duplicate');
		}

	}

	return parent;

}

// iterates over the dom
function iterateDOM(ul, level, transform) {

	ul.contents('li').each(function() {
		if($(this).children('ul').length) {
			transform.call($(this).children('ul'), level);
			iterateDOM($(this).children('ul'), level+1, transform);
		}
	});

}

// folder click handler
function onFolderClick(e, fileTree) {

	var isExpanded = false;

	if($(this).parent().hasClass('expanded')) {
		$(this).parent().removeClass('expanded');
	} else {
		$(this).parent().addClass('expanded');
		isExpanded = true;
	}

	if(fileTree.options.events['folder_click']) fileTree.options.events['folder_click'](isExpanded);
}

// file click handler
function onFileClick(e, fileTree) {
	// handle link click
	if(fileTree.options.events['file_click']) fileTree.options.events['file_click']();
}

// bubbles down a selection, so if you would check a folder,
// than all files inside that folder would get selected
// automatically
function bubbleSelection(arr, checked) {

	arr.forEach(function(item) {

		item.selected = checked;
		$(item.filetree.el).find('input').prop('checked', checked);

		if(item.children) {
			bubbleSelection(item.children, checked);
		}

	});

}

// bubbles up a selection, works kind of the same as
// bubbleSelection, but then the other direction around.
function bubbleItemParentsUp(item, cb) {

	function iterate(item) {

		if(cb) cb(item);

		if(item && item.parent) {
			iterate(item.parent);
		}

	}

	if(item)
		iterate(item);

}

// filters out extensions
function getExtensions(selection) {

	var ignore = ['DS_Store'];
	var re = /(?:\.([^.]+))?$/;
	let exts = [];
	let ext;
	let parts;

	selection.forEach(function(item) {
		ext = re.exec(item.filename);
		if(ext.index > 0 && exts.indexOf(ext[1]) == -1) {
			if(typeof ext[1] !== 'string') return;
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
	if(!checked) {
		checked = item.selected;
	}

	if(!item) {
		return;
	}

	if(checked) {

		bubbleItemParentsUp(item.parent, function(item) {
			$(item.filetree.el).find('label:first').addClass('has-selected-child');
		});

	} else {

		bubbleItemParentsUp(item.parent, function(item) {

			var has_selected_child = false;

			if(item.children) {
				item.children.forEach(function(child) {
					if(child.selected) has_selected_child = true;
				});
			}

			if(!has_selected_child) {
				$(item.filetree.el).find('label:first').removeClass('has-selected-child');
			}

		});

	}
}

// handles a file / folder selection
function selectHandler(checked, index, filetree) {

	var item = filetree.getIndex(index);

	item.selected = checked;

	if(item.children) {
		bubbleSelection(item.children, checked);
	}

	if(filetree.options.events.select) {
		filetree.options.events.select.call(filetree, item, filetree.findByProperty('selected', true));
	}

	if($(this).parent().hasClass('custom-checkbox')) {
		$(item.filetree.el).find('input:checkbox').prop('checked', checked);
	}

	if(filetree.activeIndex && (filetree.activeIndex == item.filetree.index)) {
		$(filetree.options.config.sidebar).find('header input:checkbox').prop('checked', checked);
	}

	if(item.parent) {
		parentSelectedState(item, checked);
	}

	filetree.update();

	if(filetree.selectionViewActive) {
		filetree.selectionView();
	}
}

// handles a search (in the selection view)
function searchHandler(value, selection, filetree) {

	var list = $(this).find('#selection-overview');
	list.find('[data-index]').removeClass('hidden');

	if(value.length > 0) {

		list.find('[data-index]').addClass('hidden');

		var searched = selection.filter(function(item) {
			return item.filename.toLowerCase().indexOf(value.toLowerCase()) > -1;
		}).map(function(item) {
			return '[data-index='+item.filetree.index+']';
		});

		list.find(searched.join(',')).removeClass('hidden');

		if(!searched.length) {
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
	if(!folder) return;
	function countChildren(children) {
		for(var child in children) {
			if(children[child].size) {
				size += parseInt(children[child].size);
			}
			if(children[child].children) {
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
	if(!treshold) {
		return str;
	}
	return S(str).truncate(treshold).s;
}

class FileTree {

	constructor(el, options) {

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
			expandAllFolders: function() {
				$(this.el).find('[data-type="folder"]').parent().not('.skip-auto-expand').addClass('expanded');
				this.update();
			},
			collapseAllFolders: function() {
				$(this.el).find('.expanded').removeClass('expanded');
				this.update();
			},
			selectAll: function() {
				bubbleSelection(this.data.children, true);
				this.update();
				this.selectionView();
			},
			deselectAll: function() {
				bubbleSelection(this.data.children, false);
				$(this.el).find('.has-selected-child').removeClass('has-selected-child');
				this.update();
				this.selectionView();
			},
			showSelection: function() {
				this.selectionView();
			}
		}

		if(this.options.load.url) this.load(this.options.load.url, this.options.load.params);

	}

	initialise(data) {

		this.data = {
			children: data
		};

		this.construct();

		if(this.options.events.ready) this.options.events.ready.call(this);
		if(this.options.config.autoExpand) this.interactionHandlers.expandAllFolders.call(this);
	}

	// builds the HTML from the data set
	construct() {

		itemIndex = 0;
		this.el.innerHTML = '';

		var html = build.call(this, this.data.children, document.createElement('ul'));
		this.el.appendChild(html);

		this.connectListeners();
		this.update();
		this.selectionView();

		this.each(function(item) {
			if(item.parent) {
				parentSelectedState(item, item.selected);
			}
		});

	}

	// binds event (click) listeners
	connectListeners() {

		var self = this;

		$(this.el).find('li div').bind('click', function(e) {

			var type = $(this).data('type');
			var index = $(this).find('[data-index]').data('index');
			var item = null;

			if(type == 'file') {
				self.detailView(self.getIndex(index));
			}

		});

		$(this.el).find('[data-type="folder"]').bind('click', function(e) {
			e.preventDefault();
			onFolderClick.call(this, e, self);
		});

		$(this.el).find('[data-type="file"]').bind('click', function(e) {
			e.preventDefault();
			onFileClick.call(this, e, self);
		});

		$(this.el).find('label').bind('click', function(e) {
			e.stopPropagation();
		});

		$(this.el).find('input:checkbox').on('change', function(e) {
			selectHandler.call(this, $(this).is(':checked'), $(this).parent().data('index'), self);
		});

		$("*[href^='filetree:']").bind('click', function(e) {
			e.preventDefault();
			var controlName = $(this).attr('href').split(':')[1];
			if(self.interactionHandlers.hasOwnProperty(controlName)) {
				self.interactionHandlers[controlName].call(self);
			}
		});

	}

	update() {
		$('[data-value^="filetree:totalFilesCount"]').text(itemIndex);
		$('[data-value^="filetree:selectedFilesCount"]').text(this.findByProperty('selected', true).length);
	}

	// loads file json
	load(url, properties) {
		var self = this;

		// response handler
		function handleResponse(response) {

			// configurable callback
			if(self.options.load.serialize) {
				response = self.options.load.serialize(response);
			}

			// programmatable callback loaded
			if(self.loaded && typeof self.loaded === 'function') {
				self.loaded(response);
			}

			self.initialise(response);
		}

		if(!properties) {
			$.get(url).done(handleResponse);
		} else {
			CuckooWeb.api_post("/submit/api/filetree/", properties, handleResponse, err => {
				if(self.options.load.error) {
					self.options.load.error.apply(this, err);
				}
			});
		}

		return this;
	}

	// applies a custom transform to an element from internal options
	transform(name, el, item) {
		if(this.options.transform[name]) {
			return this.options.transform[name].call(item, el, this);
		}
		return el;
	}

	// returns an item with index [index]
	getIndex(index) {

		var ret = undefined;
		if(!this.data) return ret;

		function find(arr) {
			var result;

			arr.forEach(function(item) {

				if(result) return;

				if(item.filetree.index == index) {
					result = item;
				} else {
					if(item.children) {
						result = find(item.children);
					}
				}

			});

			return result;
		}

		return find(this.data.children, index);

	}

	// returns a set of items with property [property] = value [value]
	findByProperty(property, value, arr) {

		var ret = [];

		if(!this.data) return ret;

		function find(arr) {
			arr.forEach(function(item) {

				if(item.children) {
					find(item.children);
				}

				if(item[property] === value) ret.push(item);
			});
		}

		find(this.data.children);

		return ret;

	}

	detailView(item) {

		var self = this;

		if(item.type === 'directory') return;

		var html = detailTemplate({
			item: item
		});

		this.selectionViewActive = false;
		this.detailViewActive = true;
		this.activeIndex = item.filetree.index;

		this.options.config.sidebar.innerHTML = html;

		$(this.options.config.sidebar).find('header input:checkbox').bind('change', function() {
			selectHandler.call(this, $(this).is(':checked'), item.filetree.index, self);
		});

		this.options.after.detailView.call(item, this.options.config.sidebar, this);

	}

	selectionView() {

		var self = this;

		// this variable sets a treshold for the max size of a string
		// before it will break the layout.
		let str_treshold = 30;

		var selected 	 = this.findByProperty('selected', true);
		var extensions   = getExtensions(selected);

		selected.forEach(function(item) {

			// will only ellipsify text if needed, exposing
			// a new parameter 'fname_short'. this is checked
			// conditionally by Handlebars.
			if(item.filename && item.filename.length > str_treshold) {
				item.fname_short = ellipseText(item.filename, str_treshold);
			}

			// same goes for the relative path
			if(item.relapath && item.relapath.length > str_treshold) {
				// allow treshold + 10, since this text has more space.
				item.rpath_short = ellipseText(item.relapath, str_treshold + 10);
			}
		});

		var html = selectionTemplate({
			selection: selected,
			empty: (selected.length <= 0),
			extensions: extensions
		});

		this.detailViewActive = false;
		this.activeIndex = null;
		this.selectionViewActive = true;

		this.options.config.sidebar.innerHTML = html;

		$(this.options.config.sidebar).find('a').bind('click', function(e) {
			e.preventDefault();
			var item = self.getIndex(parseInt($(this).attr('href')));
			self.detailView(item);
		});

		$(this.options.config.sidebar).find('#search-selection').bind('keyup', function(e) {
			searchHandler.call(self.options.config.sidebar, this.value, selected, self);
			$(self.options.config.sidebar).find('.extension-select select').find('option:first-child').prop('selected', true);
			$(self.options.config.sidebar).find('.extension-select select').addClass('none-selected');
		});

		$(this.options.config.sidebar).find('.extension-select select').bind('change', function(e) {
			searchHandler.call(self.options.config.sidebar, '.' + this.value, selected, self);
			$(self.options.config.sidebar).find('#search-selection').val('');
			$(self.options.config.sidebar).find('.extension-select select').removeClass('none-selected');
		});

		this.options.after.selectionView.call(selected, this.options.config.sidebar, this);

	}

	serialize() {

		function diff(changed_properties, per_file_options) {
			var ret = {};

			for(var prop in changed_properties) {
				ret[changed_properties[prop]] = per_file_options[changed_properties[prop]];
			}

			return ret;
		}

		var selection = this.findByProperty('selected', true);
		return selection.map(function(item) {
			var ret = {};
			for(var prop in item) {
				if(prop !== 'filetree') {
					ret[prop] = item[prop];
				}
			}
			return ret;
		}).map(function(item) {

			var per_file_options = {};

			item.options = diff(item.changed_properties, item.per_file_options);

			// deletes all filetree specific properties from this item
			// (the properties that are sent out as JSON)
			if(item.filetree)
				delete item.filetree;

			// if(item.changed_properties)
			// 	delete item.changed_properties;

			if(item.parent)
				delete item.parent;

			if(item.fname_short)
				delete item.fname_short;

			if(item.rpath_short)
				delete item.rpath_short;

			return item;
		});
	}

	// iterator: each'es over the loaded data set
	each(callback) {

		function iterate(arr, cb) {

			arr.forEach(function(item) {

				if(item.children) {
					iterate(item.children, callback);
				}

				if(cb && typeof cb === 'function') cb(item);
			});
		}

		iterate(this.data.children, callback);

	}

	// static iterator: throw in any 'children[Array]' nested array (or for this particular case:
	// a json string representing a file structure) to loop it through
	static iterateFileStructure(arr, callback) {

		var level = 0;

		function iterate(arr, cb, parent) {

			arr.forEach(function(item, i) {

				// appends the parent to the item
				if(parent) {
					item.parent = parent;
				}

				if(item.children) {
					iterate(item.children, callback, item);
				}

				if(cb && typeof cb === 'function') cb(item);

			});

		}

		iterate(arr, callback);

	}

	static getParentContainerName(item) {
		// this function will bubble up all 'parent' entities until we reach
		// the first level. This is considered to be the 'parent' item.

		var ret = {};

		function bubbleUp(parent) {
			if(parent.parent) {
				bubbleUp(parent.parent);
			} else {
				ret = parent;
			}
		}

		if(item.parent) {
			bubbleUp(item.parent);
		}

		return ret;

	}

}

// creates a tiny data label
function Label(name, content, elementTagName) {
	if(!elementTagName) elementTagName = 'span';
	var _$ = document.createElement(elementTagName);
	_$.classList.add('label');
	_$.classList.add('label-' + name);
	_$.innerHTML = content;
	return _$;
}

// utility function for humanizing bytes
function humanizeBytes(bytes, si) {
    var thresh = si ? 1000 : 1024;
    if(Math.abs(bytes) < thresh) {
        return bytes + ' B';
    }
    var units = si
        ? ['kB','MB','GB','TB','PB','EB','ZB','YB']
        : ['KiB','MiB','GiB','TiB','PiB','EiB','ZiB','YiB'];
    var u = -1;
    do {
        bytes /= thresh;
        ++u;
    } while(Math.abs(bytes) >= thresh && u < units.length - 1);
    return bytes.toFixed(1)+' '+units[u];
}

/*
	TimeoutError: QueuePool limit of size 5 overflow 10 reached, connection timed out, timeout 30
	[31/Jan/2017 13:19:47] "GET /submit/pre/25/ HTTP/1.1" 500 10890
	- Broken pipe from ('127.0.0.1', 60662)
 */

export { FileTree, Label, humanizeBytes, folderSize, DEFAULT_FILETREE_CONFIG };
