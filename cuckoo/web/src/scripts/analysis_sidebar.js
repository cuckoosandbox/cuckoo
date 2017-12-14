class AnalysisSidebar {

	constructor(_$) {

		this.$ = _$;
		this.searchInput = this.$.find('input[name="sidebar_search"]');

		this.open = false;
		this.locked = false;
		this.search_active = false;

		if(!window.localStorage.getItem('cuckoo-sidebar-locked')) {
			window.localStorage.setItem('cuckoo-sidebar-locked', 'false');
		} else {
			window.localStorage.getItem('cuckoo-sidebar-locked') == 'true' ? this.lock() : null;
		}

		this.activateListeners();
		this.scrollHandler();

	}

	activateListeners() {

		let self = this;

		// enable mouse opening
		this.$.bind('mouseenter', function(e) {
			self.onMouseEnter(e);
		}).bind('mouseleave', function(e) {
			self.onMouseOut(e);
		});

		// disable scrolling the nav
		$(document).on('scroll', function(e) {
			e.preventDefault();
			return self.scrollHandler(e);
		});

		this.$.find('[href^=sidebar]').bind('click', function(e) {
			e.preventDefault();
			var action = $(this).attr('href').split(':')[1];

			switch(action) {
				case 'toggle-lock':
					self.toggleLock();
				break;
			}

		});

		this.searchInput.bind('keyup', function(e) {
			self.searchHandler(e, $(this).val());
		});

	}

	onMouseEnter(e) {
		this.open = true;
		this.$.addClass('open');
	}

	onMouseOut(e) {
		if(!this.search_active) {
			this.open = false;
			this.$.removeClass('open');
		}
	}

	scrollHandler(e) {
		var top = $(window).scrollTop();
		this.$.find('.cuckoo-nav').css('transform','translate3d(0,'+top+'px,0)');
	}

	lock() {
		this.locked = true;
		this.$.addClass('locked');
		window.localStorage.setItem('cuckoo-sidebar-locked', true);
	}

	unlock() {
		this.locked = false;
		this.$.removeClass('locked');
		window.localStorage.setItem('cuckoo-sidebar-locked', false);
	}

	toggleLock() {
		if(this.locked) {
			this.unlock();
		} else {
			this.lock();
		}
	}

	searchHandler(e, value) {

		if(value.length > 0) {
			this.search_active = true;
		} else {
			this.search_active = false;
		}

	}

}

$(function() {

	var sidebar;
	if($("#analysis-nav").length) sidebar = new AnalysisSidebar($('#analysis-nav'));

});
