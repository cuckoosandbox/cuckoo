import * as InterfaceControllers from './InterfaceControllers';
import * as FileTree from './FileTree';

const DEFAULT_ANALYSIS_CONFIG = {
	container: null,
	filetree: FileTree.DEFAULT_FILETREE_CONFIG
}

function createFileTree(element, config) {
	var filetree = new FileTree.FileTree(element, config);
	return filetree;
}

class AnalysisInterface {

	constructor(options) {
		this.options = $.extend(true, DEFAULT_ANALYSIS_CONFIG, options);
		this.filetree = createFileTree(this.options.container.querySelector('#filetree'), this.options.filetree);
		this.form = new InterfaceControllers.Form(this.options.form);
	}

	getData() {
		var form_values = this.form.serialize();
		form_values.file_selection = this.filetree.serialize();
		return form_values;
	}

}

export { AnalysisInterface }