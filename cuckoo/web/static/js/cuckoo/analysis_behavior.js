"use strict";

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

/*
 * Copyright (C) 2010-2013 Claudio Guarnieri.
 * Copyright (C) 2014-2016 Cuckoo Foundation.
 * This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
 * See the file 'docs/LICENSE' for copying permission.
 *
 */

// @TO-DO: cleanup jQuery selectors / comment code / trigger loading indicator

var SummaryBehaviorDetail = function () {
    function SummaryBehaviorDetail(task_id, pname, pid, category, val) {
        _classCallCheck(this, SummaryBehaviorDetail);

        this.task_id = task_id;
        this.pname = pname;
        this.pid = pid;
        this.category = category;
        this.val = val;
        this.limit = 5;
        this.offset = 0;

        this._setup = false;
        this._sel = $("section#summary div#summary_" + this.category);
    }

    _createClass(SummaryBehaviorDetail, [{
        key: "start",
        value: function start(offset, limit) {
            var params = {
                "task_id": this.task_id,
                "pid": this.pid,
                "watcher": this.val,
                "pname": this.pname
            };

            if (offset != null) params["offset"] = offset;else params["offset"] = this.offset;
            if (limit != null) params["limit"] = limit;else params["limit"] = this.limit;

            var self = this;

            CuckooWeb.api_post("/analysis/api/task/behavior_get_watcher/", params, function (data) {
                self.start_cb(data, self);
            });
        }
    }, {
        key: "_setup_html",
        value: function _setup_html(context) {
            var html = "\n            <li id=\"cat_" + context.val + "\" class=\"list-group-item\">\n                <p><b>" + context.val + "</b></p>\n                <ul id=\"" + context.val + "\"></ul>\n                <p class=\"btn_action\">\n                    <span class=\"load_more\">Load more</span> | <span class=\"load_all\">Load all</span>\n                </p>\n            </li>";

            context._sel.find("ul#" + context.pid).append(html);
            context._sel.find("ul#" + context.pid + " #cat_" + context.val + " .btn_action .load_more").click(function () {
                context.more();
            });
            context._sel.find("ul#" + context.pid + " #cat_" + context.val + " .btn_action .load_all").click(function () {
                context.all();
            });

            context._setup = true;
        }
    }, {
        key: "start_cb",
        value: function start_cb(data, context) {
            if (!context._setup) context._setup_html(context);
            var sel = context._sel.find("ul#" + context.pid + " #cat_" + context.val);

            if (data["data"].length < context.limit && context.offset != 0) {
                sel.find(".btn_action").html("<span class=\"no_results\">No more results...</span>");
            } else if (data["data"].length < context.limit && context.offset == 0) {
                sel.find(".btn_action").hide();
            }

            var html = "";
            data["data"].forEach(function (obj, i) {
                html += "<li>" + obj + "</li>";
            });

            sel.find("ul#" + context.val).append(html);
        }

        /**
         * Lazyloads more list items
         * @return
         */

    }, {
        key: "more",
        value: function more() {
            this.offset += this.limit;
            this.start();
        }

        /**
         * Clears the list and fetches everything
         * @return
         */

    }, {
        key: "all",
        value: function all() {
            SummaryBehaviorDetail.clear_list(this);
            SummaryBehaviorDetail.clear_ctrl_btns(this);

            this.start(0, 0); // fetch all
        }

        /**
         * Clears li items
         * @return
         */

    }], [{
        key: "clear_list",
        value: function clear_list(context) {
            context._sel.find("ul#" + context.pid + " #cat_" + context.val + " ul#" + context.val).html("");
        }

        /**
         * Clears the buttons
         * @return
         */

    }, {
        key: "clear_ctrl_btns",
        value: function clear_ctrl_btns(context) {
            context._sel.find("ul#" + context.pid + " #cat_" + context.val + " .btn_action").hide();
        }
    }]);

    return SummaryBehaviorDetail;
}();

var SummaryBehaviorController = function () {
    function SummaryBehaviorController(task_id, pname, pid) {
        _classCallCheck(this, SummaryBehaviorController);

        this.task_id = task_id;
        this.pname = pname;
        this.pid = pid;
        this.loading = false;
        this.loader = new Loader($(".loading"));

        this.behavioral_details = [];
    }

    _createClass(SummaryBehaviorController, [{
        key: "start",
        value: function start() {
            var params = { "task_id": this.task_id, "pid": this.pid };
            var self = this;

            CuckooWeb.api_post("/analysis/api/task/behavior_get_watchers/", params, function (data) {
                self.start_cb(data, self);
            });
        }
    }, {
        key: "start_cb",
        value: function start_cb(data, context) {
            $.each(data["data"], function (key, val) {
                var category = key;

                var sel = $("div#summary_" + category);
                sel.append("\n                <div class=\"panel panel-default\">\n                    <div class=\"panel-heading\"><h3 class=\"panel-title\">" + context.pname + " <small>pid: " + context.pid + "</small></h3></div>\n                    <ul id=\"" + context.pid + "\" class=\"list-group\">\n                    </ul>\n                </div>");

                $.each(val, function (i, obj) {
                    var behavior_detail = new SummaryBehaviorDetail(context.task_id, context.pname, context.pid, category, obj);
                    behavior_detail.start();
                    context.behavioral_details.push(behavior_detail);
                });
            });
        }
    }], [{
        key: "toggle_loading",
        value: function toggle_loading() {
            this.loader.toggle();
        }
    }]);

    return SummaryBehaviorController;
}();

var SummarySimplifier = function () {
    function SummarySimplifier(el) {
        _classCallCheck(this, SummarySimplifier);

        this.el = el;
        this._simplified = false;
        this._keepQuery = 'keep';
        this._hideQuery = 'hide';
        this._callbacks = {
            on: [],
            off: []
        };
        return this.initialise();
    }

    _createClass(SummarySimplifier, [{
        key: "initialise",
        value: function initialise() {

            var _self = this;

            this.el.on('click', function (e) {
                e.preventDefault();
                _self.toggle();
            });

            if ($('body').attr('data-simplified') === 'true') {
                this._simplified = true;
                this._update();
            } else {
                this._simplified = false;
                this._update();
            }

            return this;
        }
    }, {
        key: "toggle",
        value: function toggle() {

            if (this._simplified) {
                this._off();
            } else {
                this._on();
            }

            this._save();
        }
    }, {
        key: "_off",
        value: function _off() {
            this._simplified = false;
            this._update();
        }
    }, {
        key: "_on",
        value: function _on() {
            this._simplified = true;
            this._update();

            for (var cb in this._callbacks.on) {
                this._callbacks.on[cb]();
            }
        }
    }, {
        key: "_update",
        value: function _update(preset) {

            if (this._simplified) {
                this.el.addClass('active');
                this.el.find('span').text('default overview');
                $('body').attr('data-simplified', "true");
            } else {
                this.el.removeClass('active');
                this.el.find('span').text('simplify overview');
                $('body').attr('data-simplified', 'false');
            }
        }
    }, {
        key: "_save",
        value: function _save() {
            Cookies("simplified_view", this._simplified, { expires: 365 * 10 });
        }

        // adds 'listener' callbacks, like events

    }, {
        key: "listen",
        value: function listen(namespace, fn) {
            this._callbacks[namespace].push(fn);
        }
    }]);

    return SummarySimplifier;
}();

$(function () {

    var simplifier;

    if ($("#toggle-simplified").length) {
        simplifier = window.simplifier = new SummarySimplifier($("#toggle-simplified"));
    }

    // since the pew pew won't draw if it's invisible
    if (window.pewpew && typeof window.pewpew === 'function') {
        if (simplifier) {
            if (!simplifier._simplified) {
                simplifier.listen('on', function () {
                    window.pewpew();
                });
                return;
            } else {
                window.pewpew();
            }
        } else {
            window.pewpew();
        }
    }
});
//# sourceMappingURL=analysis_behavior.js.map
