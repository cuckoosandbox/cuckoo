'use strict';

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

/*
    @description  A function that takes in some headers as a string containing newlines. 
                  It will split the string on its newlines, and then will split it into
                  a key-value pair for easy deploying into HTML.

    @param headerStr [String]
    @returns headers [Array]
 */
function parseHeaderString(headerStr) {

    var header_lines = headerStr.split(/\r?\n/);

    var headers = header_lines.map(function (item) {
        return item.split(':');
    }).map(function (item) {

        if (item.length == 1) {
            return {
                name: null,
                value: item[0]
            };
        } else {
            return {
                name: item[0],
                value: item[1]
            };
        }
    });

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
        this.request_headers = this.el.find('[data-contents=request-headers]').html();
        this.response_headers = this.el.find('[data-contents=response-headers]').html();
        this.request_body = null;
        this.response_body = null;

        // display modes, controls what the user will see in the body field
        this.displayBody = 'response';
        this.displayOutput = 'hex';
        this.displayMode = 16;

        // actions
        this.actions = options.actions ? options.actions : {};

        this.initialise();
    }

    _createClass(RequestDisplay, [{
        key: 'initialise',
        value: function initialise() {

            var _this = this;

            // create static header fields from a headers string to a table
            var requestHeadersTable = RequestDisplay.createHeaderTable(this.request_headers);
            var responseHeadersTable = RequestDisplay.createHeaderTable(this.response_headers);

            this.el.find('[data-draw=request-headers]').after(requestHeadersTable);
            this.el.find('[data-draw=response-headers]').after(responseHeadersTable);

            // cleans up init garbage from html
            this.el.find('.removable').remove();

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
                    self.actions[action].apply(self, [actionValue, self.el]);
                }

                $(this).parent().find('.btn').removeClass('active');
                $(this).addClass('active');

                // draws the new body view
                self.bodyViewMode();
            });

            this.bodyViewMode(function (data) {
                self.open();
            });
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

        /*
            This function 'decides' what the user gets to see and controls
            that behavior.
         */

    }, {
        key: 'bodyViewMode',
        value: function bodyViewMode(cb) {

            // read-only vars
            var displayBody = this.displayBody;
            var outputMode = this.displayOutput;
            var displayMode = this.displayMode;

            // private functions
            function renderHex(str) {
                return hexy(base64.decode(str), {
                    width: displayMode ? displayMode : 16,
                    html: true
                });
            }

            function renderPlaintext(str) {
                return base64.decode(str);
            }

            // private vars
            var content;

            // set the content we're working with based on what the user wants (response/request body)
            displayBody == 'response' ? content = this.response_body : content = this.request_body;

            // parse this content to our output results
            outputMode == 'hex' ? content = renderHex(content) : content = renderPlaintext(content);

            // draw this into the container
            this.el.find('[data-draw=http-body]').empty().text(content);

            if (cb && typeof cb === 'function') cb(content);
        }

        /*
            Takes in a headerString, passes it to a handlebars template
            that will draw the table for me.
         */

    }], [{
        key: 'createHeaderTable',
        value: function createHeaderTable(headers) {
            var tableTemplate = HANDLEBARS_TEMPLATES['header-table'];
            return tableTemplate({
                keyv: parseHeaderString(headers)
            });
        }
    }]);

    return RequestDisplay;
}();

$(function () {

    $("#http-requests .network-display__request").each(function () {
        var rd = new RequestDisplay($(this), {
            actions: {
                display: function display(value, $parent) {
                    this.displayBody = value;
                },
                output: function output(value, $parent) {

                    if (value == 'hex') {
                        $parent.find('.tab-mode').show();
                    } else {
                        $parent.find('.tab-mode').hide();
                    }

                    this.displayOutput = value;
                },
                mode: function mode(value, $parent) {
                    this.displayMode = parseInt(value);
                }
            }
        });
    });

    // page navigation for network analysis pages
    // this will move to a more abstract and re-usable utility following
    // underneath simple code
    $(".network-analysis-groups > a").bind('click', function (e) {
        e.preventDefault();
        $(".network-analysis-groups > a").removeClass('active');
        $(this).addClass('active');
        $('.network-analysis-pages > div').removeClass('active');
        $('.network-analysis-pages > ' + $(this).attr('href')).addClass('active');
    });
});
//# sourceMappingURL=analysis_network.js.map
