"use strict";

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

/*
 * Copyright (C) 2016-2018 Cuckoo Foundation.
 * This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
 * See the file 'docs/LICENSE' for copying permission.
 *
 */

var Recent = function () {
    function Recent() {
        _classCallCheck(this, Recent);

        this.loading = false;
        this.loader = new Loader($('.loading'));
        this.limit = 100;
        this.offset = 0;
        this.empty_results = false;

        this.params = {
            "cats": [],
            "packs": [],
            "score": ""
        };
    }

    _createClass(Recent, [{
        key: "toggle_loading",
        value: function toggle_loading() {
            if (this.loader.loading) {
                this.loader.stop();
            } else {
                this.loader.start();
            }
        }
    }, {
        key: "gather_params",
        value: function gather_params() {
            // reset everything to default values
            $("div#no_more_results").hide();

            function is_active(data_filter) {
                return $("div.nav_container>div a[data-filter=" + data_filter + "]").parent().hasClass("active");
            }

            if (is_active("cat_files")) this.params["cats"].push("file");
            if (is_active("cat_urls")) this.params["cats"].push("url");

            if (is_active("score_0-4")) {
                this.params["score"] = "0-4";
            } else if (is_active("score_4-7")) {
                this.params["score"] = "4-7";
            } else if (is_active("score_7-10")) {
                this.params["score"] = "7-10";
            }

            //if(is_active('pack_pdf')) this.params['packs'].push('pdf');
            //if(is_active('pack_office')) this.params['packs'].push('office');

            return this.params;
        }

        /**
         * Contacts API
         * @param {Object} [params] - filters
         * @param {Function} callback - the callback function
         * @return
         */

    }, {
        key: "get_tasks",
        value: function get_tasks() {
            var params = this.gather_params();
            params["offset"] = this.offset;
            params["limit"] = this.limit;

            var self = this;

            function cb(data) {
                self.results_callback(data);
                self.toggle_loading();
            }

            function beforesend() {
                self.toggle_loading();
            }

            CuckooWeb.api_post("api/tasks/recent/", params, cb, null, beforesend);
        }
    }, {
        key: "load",
        value: function load() {
            $("#recent>tbody").html("");
            this.empty_results = false;
            this.offset = 0;
            this.params = {
                "cats": [],
                "packs": [],
                "score": ""
            };
            this.get_tasks();
        }
    }, {
        key: "lazy_load",
        value: function lazy_load() {
            this.offset += this.limit;
            this.get_tasks();
        }
    }, {
        key: "results_callback",
        value: function results_callback(data) {
            data = data.tasks;
            if (Object.keys(data).length == 0) {
                $("div#no_more_results").show();
                $("div#no_more_results>span").html("no more results");
                this.empty_results = true;
            } else {
                data.forEach(function (analysis, i) {

                    // escape entities to ensure xss safety
                    analysis.target = CuckooWeb.escapeHTML(analysis.target || "");

                    var html = "<tr><td>";

                    html += "<strong>" + analysis["id"] + "</strong></td><td>";

                    var date_completed_on = "-";
                    var date_added_on = "-";

                    if (analysis.hasOwnProperty("completed_on")) date_completed_on = CuckooWeb.getFormattedDate(analysis.completed_on);
                    if (analysis.hasOwnProperty("added_on")) date_added_on = CuckooWeb.getFormattedDate(analysis.added_on);

                    if (analysis.status == "reported" || analysis.status == "failed_analysis") {
                        html += "<a href=\"" + analysis.id + "/summary\"><span class=\"mono\">" + date_completed_on + "</span></a>";
                    } else {
                        html += "<span class=\"mono muted\">" + date_added_on + "</span>";
                    }

                    html += "</td><td>";

                    if (analysis.status == "reported" || analysis.status == "failed_analysis") {
                        html += "<a href=\"" + analysis.id + "/summary\"><span class=\"mono\">" + analysis.md5 + "</span></a>";
                    } else {
                        html += "<span class=\"mono\">" + analysis.md5 + "</span>";
                    }

                    html += "</td><td>";

                    if (analysis.status == "reported" || analysis.status == "failed_analysis") {
                        html += "<a href=\"" + analysis.id + "/summary\">" + analysis.target + "</a>";
                    } else {
                        html += analysis.category;
                    }

                    html += "</td><td>";

                    if (analysis.status == "pending") {
                        html += '<span class="text-muted">pending</span>';
                    } else if (analysis.status == "running") {
                        html += '<span class="text-warning">running</span>';
                    } else if (analysis.status == "completed") {
                        html += '<span class="text-info">completed</span>';
                    } else if (analysis.status == "reported") {
                        if (analysis.errors) {
                            html += '<span class="text-danger">';
                        } else {
                            html += '<span class="text-success">';
                        }

                        html += "reported</span>";
                    } else {
                        html += "<span class=\"text-danger\">" + analysis.status + "</span>";
                    }

                    html += "</td><td>";

                    var badge_color = "default";
                    if (analysis.hasOwnProperty("score")) {
                        if (analysis.score >= 4 && analysis.score <= 7) badge_color = "warning";else if (analysis.score > 7) badge_color = "danger";
                    }

                    html += "<span class=\"badge badge-" + badge_color + "\">score: " + analysis.score + "</span>";
                    html += "</td></tr>";

                    $("table#recent tbody").append(html);
                });
            }
        }
    }]);

    return Recent;
}();
//# sourceMappingURL=recent.js.map
