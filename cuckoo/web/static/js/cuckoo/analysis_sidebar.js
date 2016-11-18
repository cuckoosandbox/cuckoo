'use strict';

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

var AnalysisSidebar = function () {
	function AnalysisSidebar(_$) {
		_classCallCheck(this, AnalysisSidebar);

		this.$ = _$;
		this.open = false;

		this.activateListeners();
	}

	_createClass(AnalysisSidebar, [{
		key: 'activateListeners',
		value: function activateListeners() {

			this.$.bind('mouseenter', function (e) {
				this.onMouseEnter(e);
			}.bind(this)).bind('mouseleave', function (e) {
				this.onMouseOut(e);
			}.bind(this));
		}
	}, {
		key: 'onMouseEnter',
		value: function onMouseEnter(e) {
			this.$.addClass('open');
		}
	}, {
		key: 'onMouseOut',
		value: function onMouseOut(e) {
			this.$.removeClass('open');
		}
	}]);

	return AnalysisSidebar;
}();

$(function () {

	var sidebar = new AnalysisSidebar($('#analysis-nav'));
	console.log(sidebar);
});
//# sourceMappingURL=analysis_sidebar.js.map
