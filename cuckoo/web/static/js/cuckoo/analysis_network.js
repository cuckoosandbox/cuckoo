'use strict';

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

function parseHeaderString(headerStr) {
    var headers = {};
    var header_lines = headerStr.split(/\r?\n/);
    for (var header in header_lines) {
        var keyv = header_lines[header].split(':');
        if (keyv.length == 1) {
            headers['url'] = keyv[0];
        } else {
            headers[keyv[0]] = keyv[1];
        }
    }
    return headers;
}

/*
	new HTTP layout helper
 */

var RequestDisplay = function () {
    function RequestDisplay(el, options) {
        _classCallCheck(this, RequestDisplay);

        // element
        this.el = el;

        // flags
        this.isLoading = false;
        this.isLoaded = false;
        this.isOpen = false;

        // request-specific parameters
        this.index = this.el.data('index');
        this.protocol = this.el.data('protocol');
        this.request_headers = parseHeaderString(this.el.find('[data-contents=request-headers]').html());
        this.response_headers = parseHeaderString(this.el.find('[data-contents=response-headers]').html());
        this.request_body = null;
        this.response_body = null;

        console.log(this);

        // actions
        this.actions = options.actions ? options.actions : {};

        this.el.find('[data-contents=response-headers], [data-contents=request-headers]').remove();

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

            $.post("/analysis/api/task/network_http_data/", JSON.stringify({
                "task_id": window.task_id,
                "protocol": _this.protocol,
                "request_body": false,
                "request_index": _this.index
            }), function (data) {
                _this.request_body = data.request;
                _this.response_body = data.response;
                _this.loadFinish(data, summaryElement);
            });
        }

        /*
        called by the load function when it ends, will process 
        the response and start opening the panel.
         */

    }, {
        key: 'loadFinish',
        value: function loadFinish(response, summaryElement) {

            var self = this;

            this.isLoading = false;
            this.isLoaded = true;

            this.el.removeClass('is-loading');
            summaryElement.find('.fa-chevron-right').removeClass('fa-spinner fa-spin');

            this.el.find('.flex-tabs__tab .btn').bind('click', function (e) {

                e.preventDefault();
                var keys = $(this).attr('href').split(':');
                var action = keys[0];
                var actionValue = keys[1];

                if (self.actions[action] && typeof self.actions[action] === 'function') {
                    self.actions[action](actionValue, self.el);
                }

                $(this).parent().find('.btn').removeClass('active');
                $(this).addClass('active');
            });

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
        var rd = new RequestDisplay($(this), {
            actions: {
                display: function display(value, $parent) {
                    console.log(value);
                },
                output: function output(value, $parent) {

                    console.log($parent);

                    if (value == 'hex') {
                        $parent.find('.tab-mode').show();
                    } else {
                        $parent.find('.tab-mode').hide();
                    }
                },
                mode: function mode(value, $parent) {}
            }
        });
    });

    // page navigation
    $(".network-analysis-groups > a").bind('click', function (e) {
        e.preventDefault();
        $(".network-analysis-groups > a").removeClass('active');
        $(this).addClass('active');

        $('.network-analysis-pages > div').removeClass('active');
        $('.network-analysis-pages > ' + $(this).attr('href')).addClass('active');
    });
});
//# sourceMappingURL=analysis_network.js.map
