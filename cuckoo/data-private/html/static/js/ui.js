/*
	UIKit v1.0
	- AMD wrapper help: http://gomakethings.com/the-anatomy-of-a-vanilla-javascript-plugin/
 */

(function (root, factory) {
    if ( typeof define === 'function' && define.amd ) {
        define(['UIKit'], factory(root));
    } else if ( typeof exports === 'object' ) {
        module.exports = factory(require('UIKit'));
    } else {
        root.UIKit = factory(root, root.UIKit);
    }
})(typeof global !== 'undefined' ? global : this.window || this.global, function (root) {

	var store = {};

	/*
		Collapsable
	 */
	function Collapsable(el, options) {

		if(!options) options = {};

		this.$ = el;
		this.$toggle = this.$.find('.collapse-toggle');
		this.target = this.$.find('[data-target]');

		this.isOpen = false;
		this.options = {
			close: function() {},
			open: function() {}
		};

		return this.initialise(options);
	}
	Collapsable.prototype = {

		initialise: function(options) {

			var self = this;
			this.$.addClass('collapsable');
			this.options = $.extend(this.options, options);

			// binds the listener
			this.$toggle.on('click', function(e) {
				e.preventDefault();
				this.toggle();
			}.bind(this));

			return this;
		},

		open: function() {
			this.isOpen = true;
			this.$.addClass('open');
			this.options.open.bind(this);
		},

		close: function() {
			this.options.open.bind(this);
			this.$.removeClass('open');
			this.isOpen = false;
		},

		toggle: function() {
			if(this.isOpen) {
				this.close();
			} else {
				this.open();
			}
		}

	}

	return {
		Collapsable: function(_$, options) {
			if(!store.Collapsable) store.Collapsable = [];
			var c = new Collapsable(_$, options);
			store.Collapsable.push(c);
			return c;
		},

		store: store
	};

});