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
function parseHeaderString(headerStr, extract_status_code) {

    var header_lines = headerStr.split(/\r?\n/);
    var status_code;

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

    return {
        headers: headers,
        status_code: status_code
    };
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

        // util function for storing stuff to somewhere
        this.store = options.store ? options.store : function () {};

        // request-specific parameters
        this.index = this.el.data('index');
        this.protocol = this.el.data('protocol');
        this.request_headers = this.el.find('[data-contents=request-headers]').html();
        this.response_headers = this.el.find('[data-contents=response-headers]').html();
        this.request_body = null;
        this.response_body = null;

        // display modes, controls what the user will see in the body field
        this.displayBody = options.displayBody ? options.displayBody : 'response';
        this.displayOutput = options.displayOutput ? options.displayOutput : 'hex';
        this.displayMode = options.displayMode ? options.displayMode : 16;

        // actions
        this.actions = options.actions ? options.actions : {
            display: function display() {},
            output: function output() {},
            mode: function mode() {}
        };

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
                self.store(self.displayMode, self.displayOutput, self.displayBody);
            });

            self.open();
        }

        /*
        Opens the response body and request
        details panel.
         */

    }, {
        key: 'open',
        value: function open() {
            var _this = this;

            this.bodyViewMode(function () {
                _this.el.addClass('is-open');
                _this.isOpen = true;
            });
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

            // to prevent big HTML hanging around while it's not visible
            // we clear out the response fields for speed/performance optimization. it
            // will be redrawn on 'open' again.
            this.el.find('[data-draw=http-body]').empty();
        }

        /*
            Synchronizes properties with element
         */

    }, {
        key: 'syncUI',
        value: function syncUI() {
            // syncs the mode property to ui
            this.el.find('.tab-mode > a').removeClass('active');
            this.el.find('.tab-mode > a[href="mode:' + this.displayMode + '"]').addClass('active');
            // syncs the output property to ui
            this.el.find('.tab-output > a').removeClass('active');
            this.el.find('.tab-output > a[href="output:' + this.displayOutput + '"]').addClass('active');
            // syncs the display property to ui
            this.el.find('.tab-display > a').removeClass('active');
            this.el.find('.tab-display > a[href="display:' + this.displayBody + '"]').addClass('active');

            // show/hide byte selection in hex view
            if (this.displayOutput == 'hex') {
                this.el.find('.tab-mode').show();
            } else {
                this.el.find('.tab-mode').hide();
            }
        }

        /*
            This function 'decides' what the user gets to see and controls
            that behavior.
         */

    }, {
        key: 'bodyViewMode',
        value: function bodyViewMode(cb) {

            this.syncUI();

            // this can't be done when nothing is loaded.
            if (!this.isLoaded) return;

            // read-only vars
            var displayBody = this.displayBody;
            var outputMode = this.displayOutput;
            var displayMode = this.displayMode;

            // private vars
            var content;

            // private functions
            function renderHex(str) {

                return hexy(base64.decode(str), {
                    width: displayMode ? displayMode : 16,
                    html: false
                });
            }

            function renderPlaintext(str) {
                return base64.decode(str);
            }

            // set the content we're working with based on what the user wants (response/request body)
            displayBody == 'response' ? content = this.response_body : content = this.request_body;

            // parse this content to our output results
            outputMode == 'hex' ? content = renderHex(content) : content = renderPlaintext(content);

            if (content.length == 0) {
                this.el.find('[data-draw=http-body]').addClass('empty-body');
            } else {
                this.el.find('[data-draw=http-body]').removeClass('empty-body');
            }

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
                keyv: parseHeaderString(headers).headers
            });
        }
    }]);

    return RequestDisplay;
}();

$(function () {

    var rDisplays = [];

    // persists property to other active http display elements
    function persistProperty(prop, value) {
        rDisplays.forEach(function (rdisp) {
            if (rdisp[prop] == value) return;
            rdisp[prop] = value;
            rdisp.bodyViewMode();
        });
    }

    // returns the localstorage preferences
    function getPreferences() {
        return {
            displayMode: localStorage.getItem('http-display-mode'),
            displayOutput: localStorage.getItem('http-display-output'),
            displayBody: localStorage.getItem('http-display-body')
        };
    }

    var prefs = getPreferences();

    $("#http-requests .network-display__request").each(function () {

        var rd = new RequestDisplay($(this), {
            displayMode: prefs.displayMode ? prefs.displayMode : 16,
            displayOutput: prefs.displayOutput ? prefs.displayOutput : 'hex',
            displayBody: prefs.displayBody ? prefs.displayBody : 'response',
            actions: {
                display: function display(value, $parent) {
                    this.displayBody = value;
                    persistProperty('displayBody', value);
                },
                output: function output(value, $parent) {
                    this.displayOutput = value;
                    persistProperty('displayOutput', value);
                },
                mode: function mode(value, $parent) {
                    this.displayMode = parseInt(value);
                    persistProperty('displayMode', parseInt(value));
                }
            },
            store: function store(mode, output, body) {
                console.log('before store');
                window.localStorage.setItem('http-display-mode', mode);
                window.localStorage.setItem('http-display-output', output);
                window.localStorage.setItem('http-display-body', body);
                console.log('after store');
            }
        });

        rDisplays.push(rd);
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
