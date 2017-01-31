import * as InterfaceControllers from './InterfaceControllers';
import * as FileTree from './FileTree';
import * as DnDUpload from './DnDUpload';

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

		var context = getModuleContext();
			
		if(context == 'index') {
			this.dndupload = createDnDUpload(this.options.dndupload);
			this.dndupload.draw();
		}

		if(context == 'pre') {
			this.filetree = createFileTree(this.options.container.querySelector('#filetree'), this.options.filetree);
			this.form = createForm(this.options.form);
		}

	}

	getData() {
		var _self = this;
		return {
			global: _self.form.serialize(),
			file_selection: _self.filetree.serialize()
		};
	}

}

export { AnalysisInterface }