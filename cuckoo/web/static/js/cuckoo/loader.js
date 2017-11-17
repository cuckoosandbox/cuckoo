'use strict';

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

var Loader = function () {
    function Loader(el) {
        var options = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : {};

        _classCallCheck(this, Loader);

        this.el = el ? el : $('.loading');
        this.message = '';
        this.loading = false;
        this.options = $.extend({
            animate: false,
            duration: 200
        }, options);
    }

    _createClass(Loader, [{
        key: 'start',
        value: function start(msg) {
            if (msg) this.message = msg;
            this.setText();
            this.loading = true;

            if (this.options.animate) {
                this.el.slideDown(this.options.duration);
            } else {
                this.el.show();
            }
        }
    }, {
        key: 'stop',
        value: function stop() {
            var cb = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : function () {};

            this.clearText();
            this.loading = false;

            if (this.options.animate) {
                this.el.slideUp(this.options.duration, cb);
            } else {
                this.el.hide();
                cb();
            }
        }
    }, {
        key: 'toggle',
        value: function toggle(msg) {
            if (this.loading) {
                this.stop();
            } else {
                this.start(msg);
            }
        }
    }, {
        key: 'setText',
        value: function setText() {
            this.el.find('.loading-message').text(this.message);
        }
    }, {
        key: 'clearText',
        value: function clearText() {
            this.el.find('.loading-message').text('');
        }
    }]);

    return Loader;
}();
//# sourceMappingURL=loader.js.map
