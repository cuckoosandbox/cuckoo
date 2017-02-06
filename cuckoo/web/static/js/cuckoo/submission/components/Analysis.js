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

			var context = getModuleContext();

			if (context == 'index') {
				this.dndupload = createDnDUpload(this.options.dndupload);
				this.dndupload.draw();
			}

			if (context == 'pre') {
				this.filetree = createFileTree(this.options.container.querySelector('#filetree'), this.options.filetree);
				this.form = createForm(this.options.form);
			}
		}
	}, {
		key: 'getData',
		value: function getData() {
			var _self = this;
			return {
				global: _self.form.serialize(),
				file_selection: _self.filetree.serialize()
			};
		}
	}]);

	return AnalysisInterface;
}();

exports.AnalysisInterface = AnalysisInterface;
//# sourceMappingURL=Analysis.js.map
