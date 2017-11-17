'use strict';

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

/*
  A basic class definition for an element that has to be sticky
  when a user scrolls past it. This class will make sure everything is
  calculated nicely. Made in the first instance for handling sticky
  <thead> elements. But this should apply to any element.
 */
var Sticky = function () {
  function Sticky() {
    var options = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : {};

    _classCallCheck(this, Sticky);

    this.config = $.extend({
      el: null, // a jQuery element
      parent: $(window), // a scrollable parent of the sticky element
      offset: 0, // a constant parameter that takes in account any margins in the calculation
      useObserver: window.MutationObserver !== undefined // auto-bool based on existence by default
    }, options);

    this.elTopOffset = 0;
    this.observer = null;

    this.initialise();
  }

  _createClass(Sticky, [{
    key: 'initialise',
    value: function initialise() {

      var self = this;
      var el = this.config.el;
      var parent = this.config.parent;

      // calculates the offset to the top from the target element
      this.calculate();

      // binds a scroll event
      parent.bind('scroll.Sticky', function (e) {
        self.update(e);
      });

      if (MutationObserver && this.config.useObserver) {

        // experimental: use a MutationObserver to listen to DOM changes to update
        // the current top offset parameters
        this.observer = new MutationObserver(function (mutations) {
          self.calculate();
        });

        this.observer.observe(self.config.parent[0], {
          attributeFilter: ['class'],
          subtree: true
        });
      }
    }

    // updates every scroll trigger

  }, {
    key: 'update',
    value: function update(e) {

      var scrollTop = $(e.currentTarget).scrollTop();
      var diff = scrollTop - this.elTopOffset;

      if (scrollTop > this.elTopOffset) {
        this.config.el.css('transform', 'translateY(' + diff + 'px)');
      } else {
        this.config.el.css('transform', 'translateY(0px)');
      }
    }

    // calculates the current offset of the element

  }, {
    key: 'calculate',
    value: function calculate() {
      this.elTopOffset = this.config.el.offset().top - this.config.offset;
    }

    // unsticks this element

  }, {
    key: 'unstick',
    value: function unstick() {
      this.config.parent.unbind('scroll.Sticky');
      this.observer.disconnect();
    }
  }]);

  return Sticky;
}();
//# sourceMappingURL=sticky.js.map
