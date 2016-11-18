'use strict';

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

var AnalysisSidebar = function () {
	function AnalysisSidebar(_$) {
		_classCallCheck(this, AnalysisSidebar);

		this.$ = _$;
		this.searchInput = this.$.find('input[name="sidebar_search"]');

		this.open = false;
		this.locked = false;
		this.search_active = false;

		if (!window.localStorage.getItem('cuckoo-sidebar-locked')) {
			window.localStorage.setItem('cuckoo-sidebar-locked', 'false');
		} else {
			window.localStorage.getItem('cuckoo-sidebar-locked') == 'true' ? this.lock() : null;
		}

		this.activateListeners();
		this.scrollHandler();
	}

	_createClass(AnalysisSidebar, [{
		key: 'activateListeners',
		value: function activateListeners() {

			var self = this;

			// enable mouse opening
			this.$.bind('mouseenter', function (e) {
				self.onMouseEnter(e);
			}).bind('mouseleave', function (e) {
				self.onMouseOut(e);
			});

			// disable scrolling the nav
			$(document).on('scroll', function (e) {
				e.preventDefault();
				return self.scrollHandler(e);
			});

			this.$.find('[href^=sidebar]').bind('click', function (e) {
				e.preventDefault();
				var action = $(this).attr('href').split(':')[1];

				switch (action) {
					case 'toggle-lock':
						self.toggleLock();
						break;
				}
			});

			this.searchInput.bind('keyup', function (e) {
				self.searchHandler(e, $(this).val());
			});
		}
	}, {
		key: 'onMouseEnter',
		value: function onMouseEnter(e) {
			this.open = true;
			this.$.addClass('open');
		}
	}, {
		key: 'onMouseOut',
		value: function onMouseOut(e) {
			if (!this.search_active) {
				this.open = false;
				this.$.removeClass('open');
			}
		}
	}, {
		key: 'scrollHandler',
		value: function scrollHandler(e) {
			var top = $(window).scrollTop();
			this.$.find('.cuckoo-nav').css('transform', 'translate3d(0,' + top + 'px,0)');
		}
	}, {
		key: 'lock',
		value: function lock() {
			this.locked = true;
			this.$.addClass('locked');
			window.localStorage.setItem('cuckoo-sidebar-locked', true);
		}
	}, {
		key: 'unlock',
		value: function unlock() {
			this.locked = false;
			this.$.removeClass('locked');
			window.localStorage.setItem('cuckoo-sidebar-locked', false);
		}
	}, {
		key: 'toggleLock',
		value: function toggleLock() {
			if (this.locked) {
				this.unlock();
			} else {
				this.lock();
			}
		}
	}, {
		key: 'searchHandler',
		value: function searchHandler(e, value) {

			if (value.length > 0) {
				this.search_active = true;
			} else {
				this.search_active = false;
			}
		}
	}]);

	return AnalysisSidebar;
}();

$(function () {

	var sidebar;
	if ($("#analysis-nav").length) sidebar = new AnalysisSidebar($('#analysis-nav'));
});
//# sourceMappingURL=analysis_sidebar.js.map
