'use strict';

var _typeof = typeof Symbol === "function" && typeof Symbol.iterator === "symbol" ? function (obj) { return typeof obj; } : function (obj) { return obj && typeof Symbol === "function" && obj.constructor === Symbol && obj !== Symbol.prototype ? "symbol" : typeof obj; };

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

/*
    @description  A function that takes in some headers as a string containing newlines. 
                  It will split the string on its newlines, and then will split it into
                  a key-value pair for easy deploying into HTML.

    @param headerStr [String]
    @returns headers [Array]
 */
function parseHeaderString(headerStr, debug) {

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
    working towards a single definition of the hex/plaintext
    fields for display options, as the above only works for http,
    but does not work for other components sharing this same feature.
 */

var HexView = function () {
    function HexView(el, raw, options) {
        _classCallCheck(this, HexView);

        // format if type is nog right, should be an object with different options,
        // if it's not an object, we'll assume the body is passed in completely
        if ((typeof raw === 'undefined' ? 'undefined' : _typeof(raw)) !== 'object') {
            raw = {
                'response': raw,
                'request': ''
            };
        }

        // class data
        this.el = el;
        this.raw = raw;
        this.container = options.container ? options.container : null;
        this.locked = false;

        var user_preferences = HexView.getPreferences();

        // parameters
        this.displayBody = user_preferences.displayBody ? user_preferences.displayBody : 'response';
        this.displayOutput = user_preferences.displayOutput ? user_preferences.displayOutput : 'hex';
        this.displayMode = user_preferences.displayMode ? user_preferences.displayMode : 16;

        // manual overrides of the different states, in case one it not available
        if (options.displayBody) this.displayBody = options.displayBody;
        if (options.displayOutput) this.displayOutput = options.displayOutput;
        if (options.displayMode) this.displayMode = options.displayMode;

        this.actions = $.extend({
            display: function display() {},
            output: function output() {},
            mode: function mode() {}
        }, options.actions ? options.actions : {});

        this.events = $.extend({
            click: function click() {},
            display: function display() {},
            output: function output() {},
            mode: function mode() {}
        }, options.events ? options.events : {});

        this.el.data('hexView', this);
        this.el.attr('hexview', true);

        return this;
    }

    _createClass(HexView, [{
        key: 'initialise',
        value: function initialise() {

            var _this = this;

            if (this.container) {
                this.container = this.el.find(this.container);
            }

            this.el.find('.flex-tabs__tab .btn').bind('click', function (e) {

                e.preventDefault();

                if (_this.locked) return;

                var keys = $(this).attr('href').split(':');
                var action = keys[0];
                var actionValue = keys[1];
                var propName;

                if (action == 'output') {
                    _this.displayOutput = actionValue;
                    propName = 'displayOutput';
                }
                if (action == 'mode') {
                    _this.displayMode = actionValue;
                    propName = 'displayMode';
                }
                if (action == 'display') {
                    _this.displayBody = actionValue;
                    propName = 'displayBody';
                }

                _this.actions[action].apply(_this, [actionValue, _this.el]);
                _this.events[action].apply(actionValue, _this.el);

                _this.sync();

                // save these things to user preference in localstorage
                HexView.storePreferences({
                    displayBody: _this.displayBody,
                    displayOutput: _this.displayOutput,
                    displayMode: _this.displayMode
                });

                // now persist this to EVERY active hexview to keep things awesome
                HexView.persistProperty(propName, actionValue);
            });

            this.sync();

            return this;
        }
    }, {
        key: 'sync',
        value: function sync() {

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

            this.render();
        }
    }, {
        key: 'render',
        value: function render() {

            var displayBody,
                outputMode,
                content = this.raw,
                textArea = true;

            var body = this.displayBody;
            var output = this.displayOutput;
            var mode = this.displayMode;

            output == 'hex' ? content = HexView.renderHex(content[body], mode) : content = HexView.renderPlaintext(content[body]);

            // display a message that there's an empty body if the content length is 0
            if (content.length == 0) {
                this.el.addClass('empty-body');
                // this.container.addClass('empty-body');
            } else {
                this.el.removeClass('empty-body');
                // this.container.removeClass('empty-body');
            }

            this.container.empty().text(HexView.unescapeHTML(content));
        }
    }], [{
        key: 'renderHex',
        value: function renderHex(str, mode) {

            return hexy(base64.decode(str), {
                width: mode ? parseInt(mode) : 16,
                html: false
            });
        }
    }, {
        key: 'renderPlaintext',
        value: function renderPlaintext(str) {
            return base64.decode(str);
        }
    }, {
        key: 'getPreferences',
        value: function getPreferences() {
            var prefs = window.localStorage.getItem('hex-view');
            if (prefs) {
                return JSON.parse(prefs);
            } else {
                // send defaults
                return {
                    displayMode: 16,
                    displayOutput: 'hex',
                    displayBody: 'response'
                };
            }
        }
    }, {
        key: 'storePreferences',
        value: function storePreferences(prefs) {
            prefs = $.extend({
                displayMode: 16,
                displayOutput: 'hex',
                displayBody: 'response'
            }, prefs);
            window.localStorage.setItem('hex-view', JSON.stringify(prefs));
        }
    }, {
        key: 'persistProperty',
        value: function persistProperty(property, value) {
            $("[hexview='true']").each(function () {
                var view = $(this).data('hexView');
                if (view.hasOwnProperty(property)) {
                    view[property] = value;
                    view.sync();
                }
            });
        }
    }, {
        key: 'lockAll',
        value: function lockAll(lock) {
            if (lock === true) {
                HexView.persistProperty('locked', true);
            } else {
                HexView.persistProperty('locked', false);
            }
        }

        // http://stackoverflow.com/questions/22279231/using-js-jquery-how-can-i-unescape-html-and-put-quotes-back-in-the-str

    }, {
        key: 'unescapeHTML',
        value: function unescapeHTML(safe) {
            return safe.replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#039;/g, "'");
        }
    }]);

    return HexView;
}();

/*
	HTTP layout helper
 */


var RequestDisplay = function () {
    function RequestDisplay(el) {
        _classCallCheck(this, RequestDisplay);

        // element
        this.el = el;

        // after loading, this property will be an instance of HexView
        this.hex_view = undefined;

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

            CuckooWeb.post("/analysis/api/task/network_http_data/", {
                "task_id": window.task_id,
                "protocol": _this.protocol,
                "request_body": false,
                "request_index": _this.index
            }, function (data) {
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

            this.hex_view = new HexView(this.el, {
                request: self.request_body,
                response: self.response_body
            }, {
                container: '[data-draw="source"]'
            }).initialise();

            console.log(this.hex_view);

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
            _this.el.addClass('is-open');
            _this.isOpen = true;
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
            this.el.find('[data-draw=source]').empty();
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

/* 
    class PacketDisplay
    @todo: unify the hex display body view to one class instead of defining two seperate
 */


var PacketDisplay = function () {
    function PacketDisplay(el, options) {
        _classCallCheck(this, PacketDisplay);

        this.options = $.extend({
            skip_empty: false
        }, options);

        this.nav = el.find("#requests");
        this.container = el.find("#packets");
        this.loader = el.find('.network-display__loader');
        this.template = HANDLEBARS_TEMPLATES['packet-display'];

        this.initialise();
    }

    _createClass(PacketDisplay, [{
        key: 'initialise',
        value: function initialise() {

            var _this = this;

            if (this.nav.find('.source-destination a').length) {

                this.nav.find('.source-destination a').bind('click', function (e) {
                    e.preventDefault();
                    _this.selectHandler($(this));
                });

                // on initialise, activate the first one.
                _this.selectHandler(this.nav.find('.source-destination a:first-child'));
            }
        }
    }, {
        key: 'selectHandler',
        value: function selectHandler(navElement) {

            var _this = this;
            var params = navElement.attr('href');

            if (params) {

                // start the loader
                this.loader.addClass('active');
                this.container.addClass('is-loading');
                HexView.lockAll(true);

                // load the data
                this.load(params, function (response) {

                    var html = [];

                    for (var r in response) {

                        if (_this.options.skip_empty && response[r].raw.length == 0) continue;

                        var view = new HexView($(_this.template(response[r])), response[r].raw, {
                            container: '[data-draw="source"]',
                            displayBody: 'response'
                        });

                        html.push(view);
                    }

                    _this.container.empty();

                    html.forEach(function (partial) {
                        _this.container.append(partial.el);
                        partial.initialise();
                    });

                    // stop the loader and scrolls back to top

                    var duration = 0;

                    if (_this.container.parent().scrollTop() > 0) {
                        duration = 1500;
                    }

                    _this.container.parent().animate({
                        scrollTop: 0
                    }, {
                        duration: duration,
                        specialEasing: {
                            scrollTop: "easeOutBounce"
                        },
                        complete: function complete() {
                            HexView.lockAll(false);
                            _this.loader.removeClass('active');
                            _this.container.removeClass('is-loading');
                        }
                    });
                }, function (err) {

                    console.log(err);
                });
            }
        }
    }, {
        key: 'load',
        value: function load(params, callback, err) {

            $.get('/analysis/' + window.task_id + '/pcapstream/' + params + '/').done(function (response) {
                if (callback && typeof callback == 'function') callback(response);
            }).fail(function (e) {

                console.log(e);
            });
        }
    }]);

    return PacketDisplay;
}();

// TCP/UTP packet displays


$(function () {

    // some info about alteration in layout type
    var fixed_layouts = ['network-analysis-tcp', 'network-analysis-udp'];

    // custom page-switcher implementation with callbacks
    var network_nav = new PageSwitcher({
        nav: $('.network-analysis-groups'),
        container: $('.network-analysis-pages'),
        events: {
            beforeTransition: function beforeTransition(name, page) {

                $('.cuckoo-analysis').removeClass('flex-nav__body--disable-overflow');

                // some pages require a fixed layout change, this does that
                if (fixed_layouts.indexOf(name) !== -1) {
                    $('.cuckoo-analysis').addClass('flex-nav__body--disable-overflow');
                }

                if (name == 'network-analysis-http') {
                    if (page.el.find('.no-content').length) {
                        $('.cuckoo-analysis').addClass('flex-nav__body--disable-overflow');
                    }
                }
            }
        }
    });

    // jumps to the default activated page
    network_nav.transition('network-analysis-http');

    if ($("#network-analysis-tcp").length) {

        var packet_display_tcp = new PacketDisplay($("#network-analysis-tcp"), {
            skip_empty: true
        });
    }

    if ($("#network-analysis-udp").length) {

        var packet_display_udp = new PacketDisplay($('#network-analysis-udp'), {
            skip_empty: true
        });
    }

    $("#http-requests .network-display__request").each(function () {
        var rd = new RequestDisplay($(this));
    });

    // helpers for the udp/tcp pages
    $('.source-destination .content li:first-child a').addClass('active');

    $('.source-destination .content a').bind('click', function (e) {
        e.preventDefault();
        $('.source-destination a').removeClass('active');
        $(this).addClass('active');
    });
});
//# sourceMappingURL=analysis_network.js.map
