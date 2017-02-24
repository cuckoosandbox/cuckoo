'use strict';

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

/*
	new HTTP layout helper
 */
var RequestDisplay = function () {
  function RequestDisplay(el) {
    _classCallCheck(this, RequestDisplay);

    // element
    this.el = el;

    // flags
    this.isLoading = false;
    this.isLoaded = false;
    this.isOpen = false;

    this.initialise();
  }

  _createClass(RequestDisplay, [{
    key: 'initialise',
    value: function initialise() {

      var _this = this;

      // bind a click event to the summary bar
      this.el.find('.network-display__request-summary').bind('click', function (e) {
        e.preventDefault();

        // only respond if it's not loading
        if (_this.isLoading) return;

        // if we already have the loaded data,
        // jump straight to opening, else, load
        // and then open.
        if (_this.isLoaded) {
          if (_this.isOpen) {
            _this.close();
          } else {
            _this.open();
          }
        } else {
          _this.load($(this));
        }
      });
    }

    /*
    loads the content with ajax
     */

  }, {
    key: 'load',
    value: function load(summaryElement) {
      var _this = this;

      this.isLoading = true;
      this.el.addClass('is-loading');
      summaryElement.find('.fa-chevron-right').addClass('fa-spinner fa-spin');

      // this will later be replaced by the ajax call getting the content
      setTimeout(function () {
        _this.loadFinish({}, summaryElement);
      }, 1000);
    }

    /*
    called by the load function when it ends, will process 
    the response and start opening the panel.
     */

  }, {
    key: 'loadFinish',
    value: function loadFinish(response, summaryElement) {

      this.isLoading = false;
      this.isLoaded = true;
      this.el.removeClass('is-loading');
      summaryElement.find('.fa-chevron-right').removeClass('fa-spinner fa-spin');

      this.open();
    }

    /*
    Opens the response body and request
    details panel.
     */

  }, {
    key: 'open',
    value: function open() {
      this.el.addClass('is-open');
      this.isOpen = true;
    }

    /*
    Closes the reponse body and request
    details panel.
     */

  }, {
    key: 'close',
    value: function close() {
      this.el.removeClass('is-open');
      this.isOpen = false;
    }
  }]);

  return RequestDisplay;
}();

$(function () {

  $("#http-requests .network-display__request").each(function () {
    var rd = new RequestDisplay($(this));
  });
});
//# sourceMappingURL=analysis_network.js.map
