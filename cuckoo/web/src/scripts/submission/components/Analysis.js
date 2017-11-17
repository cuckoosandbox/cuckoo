import * as InterfaceControllers from './InterfaceControllers';
import * as FileTree from './FileTree';
import * as DnDUpload from './DnDUpload';

// temporary fix for accessing DnDUpload from exterbal modules
// as import doesn't work in the old js files
window.DnDUpload = DnDUpload;

const DEFAULT_ANALYSIS_CONFIG = {
	container: null,
	filetree: FileTree.DEFAULT_FILETREE_CONFIG,
	dndupload: DnDUpload.DEFAULT_UPLOADER_CONFIG
}

function getModuleContext() {
	var id = $('body').attr('id');
	if(id.indexOf('/') > -1) {
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

class AnalysisInterface {

	constructor(options) {

		this.options = $.extend(true, DEFAULT_ANALYSIS_CONFIG, options);

		this.dndupload = null;
		this.filetree = null;
		this.form = null;

		this.originalData = null;

		this.initialise();
	}

	initialise() {

		var self    = this;
		var context = getModuleContext();

		if(context == 'index') {
			this.dndupload = createDnDUpload(this.options.dndupload);
			this.dndupload.draw();
		}

		if(context == 'pre') {
			this.filetree = createFileTree(this.options.container.querySelector('#filetree'), this.options.filetree);

			this.filetree.loaded = function() {
				self.form = createForm(self.options.form);
			}
		}

	}

	getData(extra_properties, stringified) {
		var _self = this;
		var ret = {};

		ret.global = this.form.serialize();
		ret.file_selection = this.filetree.serialize()

		// if we have extra properties, extend the return object
		// with these properties
		if(extra_properties) {
			for(var prop in extra_properties) {
				ret[prop] = extra_properties[prop];
			}
		}

		// filter out properties that are causing the json stringify to fail
		// and throw circular json errors
		ret.file_selection = ret.file_selection.map(function(item) {

			if(item.per_file_options) {
				item.options = item.per_file_options;
				delete item.per_file_options;
			}

			if(item.children) {
				delete item.children;
			}

			item.filename = CuckooWeb.unescapeHTML(item.filename);

			return item;

		});

		// auto stringify using a paremeter flag
		if(stringified) ret = JSON.stringify(ret);

		return ret;
	}

}

export { AnalysisInterface }
