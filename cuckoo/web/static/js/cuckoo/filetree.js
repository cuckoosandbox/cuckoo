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

var FileTree = function () {
    function FileTree(target, data, sflock, draw_callback) {
        _classCallCheck(this, FileTree);

        this.sel_target = target;
        this.data = data;
        this._draw_callback = draw_callback;
        this._convert_from_sflock = sflock;

        this._filters = {
            simplify_mime: true,
            simplify_magic: true,
            simplify_sizes: true,
            deselect_duplicates: true
        };

        this.stats = {
            duplicates: 0,
            files: 0,
            containers: 0,
            directories: 0,
            executables: 0,
            urls: 0
        };
    }

    /**
     * Draws the table
     */


    _createClass(FileTree, [{
        key: "draw",
        value: function draw() {
            if (!this.sel_target) throw "drawtarget needed";

            this._init();
            this._draw_callback();
        }
    }, {
        key: "refresh",
        value: function refresh() {
            this._reset_stats();
            var data = null;

            if (this._convert_from_sflock) {
                data = this._convert_sflock();
            } else {
                data = this.data;
            }

            $(this.sel_target).jstree(true).settings.core.data = data;
            $(this.sel_target).jstree(true).refresh();

            this._draw_callback();
        }

        /**
         * Init the table
         */

    }, {
        key: "_init",
        value: function _init() {
            var data = null;

            if (this._convert_from_sflock) {
                data = this._convert_sflock();
            } else {
                data = this.data;
            }

            var theme_active = Cookies.get("theme");
            var themes = { "name": "default" };

            if (theme_active == "night" || theme_active == "cyborg") {
                themes["name"] = "default-dark";
            }

            $(this.sel_target).jstree({
                core: {
                    data: data,
                    "multiple": true,
                    "animation": 0,
                    "themes": themes
                },
                checkbox: {
                    three_state: false,
                    cascade: 'undetermined'
                },
                types: {
                    "container": {
                        "icon": "fa fa-file-archive-o"
                    },
                    "file": {
                        "icon": "fa fa-file-o"
                    },
                    "exec": {
                        "icon": "fa fa-file-text"
                    },
                    "office": {
                        "icon": "fa fa-file-word-o"
                    },
                    "duplicate": {
                        "icon": "fa fa-ban"
                    },
                    "url": {
                        "icon": "fa fa-external-link"
                    }
                },
                grid: {
                    columns: [{ width: "auto", header: "File" }, { width: "auto", header: "Package", value: "package" }, { width: "auto", header: "Mime", value: "mime" }, { width: "auto", header: "Size", value: "size" }, { width: "10px", header: "Magic", value: "magic" }],
                    resizable: true
                },
                plugins: ["themes", "types", "checkbox", "grid", "wholerow"]
            });

            $(this.sel_target).bind("ready.jstree", function () {
                var sel_wrapper = $(".jstree-grid-wrapper");
                sel_wrapper.css("min-height", sel_wrapper.outerHeight());
            });
        }

        /**
         * Convert data from the `sflock` format to JSTree
         * @private
         */

    }, {
        key: "_convert_sflock",
        value: function _convert_sflock() {
            var data = $.extend({}, this.data); //shallow copy

            var data_tmp = [];
            for (var key in data) {
                if (data.hasOwnProperty(key)) {
                    var entry = data[key];
                    var converted = void 0;

                    if (entry.hasOwnProperty("type") && entry.type == "container") {
                        converted = this._convert_entry(data[key], entry.filename);
                    } else {
                        converted = this._convert_entry(data[key], "");
                    }

                    data_tmp.push(converted);
                }
            }

            return data_tmp;
        }
    }, {
        key: "_convert_entry",
        value: function _convert_entry(entry, parent_archive) {
            var _self = this;

            // Normalize entry object
            if (entry.size === "undefined") {
                entry.size = 0;
            }
            entry.extrpath = entry.extrpath ? entry.extrpath : [];
            if (entry.extrpath) {
                entry.filepath = parent_archive + "/" + entry.extrpath.join("/");
            } else if (!entry.filepath && entry.relapath) {
                entry.filepath = entry.relapath;
            } else if (!entry.relapath) {
                entry.relapath = entry.filepath;
            }

            // The JSTree return object
            var data = {
                text: entry.filename,
                data: {},
                a_attr: {
                    sha256: entry.sha256,
                    package: entry.package,
                    type: entry.type
                }
            };

            if (entry.hasOwnProperty("package")) {
                data.data.package = entry.package;
            }

            if (entry.type == "directory") {
                entry.type = "directory";
                entry.opened = true;
                data.state = {
                    opened: entry.opened
                };

                _self.stats.directories += 1;
            } else {
                data.data.mime = entry.mime;
                data.data.size = entry.size;
                data.data.magic = entry.magic;

                if (entry.type == "url") {
                    _self.stats.urls += 1;
                    _self.stats.files += 1;
                } else {
                    _self.stats.files += 1;
                }

                // simplify filters
                if (this._filters.simplify_magic) {
                    entry.magic = entry.finger.magic_human;
                } else {
                    entry.magic = entry.finger.magic;
                }

                if (this._filters.simplify_mime) {
                    entry.mime = entry.finger.mime_human;
                } else {
                    entry.mime = entry.finger.mime;
                }

                if (this._filters.simplify_sizes && !entry.size instanceof String) {
                    entry.size = CuckooWeb.human_size(entry.size, true);
                }

                // Sanitize object properties
                if (entry.magic) {
                    if (entry.magic.length >= 170) {
                        entry.magic = entry.magic.substring(0, 170) + "...";
                    }
                } else {
                    entry.magic = "Empty";
                }

                [".exe", ".pdf", ".vbs", ".vba", ".bat", ".py", ".pyc", ".pl", ".rb", ".js", ".jse"].forEach(function (x) {
                    if (entry.filepath.endsWith(x)) {
                        entry.type = "exec";
                        entry.state = true;

                        _self.stats.executables += 1;
                    }
                });

                [".doc", ".docx", ".docm", ".dotx", ".dotm", ".docb", "hwp", ".xltm", ".xls", ".xltx", ".xlsm", ".xlsx", ".xlt", ".ppt", ".pps", ".pot"].forEach(function (x) {
                    if (entry.filepath.endsWith(x)) {
                        entry.type = "office";
                        entry.state = true;

                        _self.stats.executables += 1;
                    }
                });

                entry.state = entry.selected;

                if (entry.duplicate) {
                    entry.type = "duplicate";

                    // Deselect duplicate file entries depending on the filter settings
                    if (this._filters.deselect_duplicates) {
                        entry.state = false;
                    }

                    // Set class for CSS
                    data.a_attr.filetree_duplicate = "true";

                    // Update stats
                    _self.stats.duplicates += 1;
                }

                data.a_attr.filepath = entry.extrpath.unshift(parent_archive) ? entry.extrpath : [entry.filepath];

                if (entry.children.length >= 1) {
                    entry.type = "container";
                    entry.opened = true;
                    _self.stats.containers += 1;
                }

                data.a_attr.filetree_type = entry.type;
                data.type = entry.type;
                data.state = {
                    selected: entry.state,
                    opened: entry.opened
                };
            }

            // Recurse this function for the child entries
            if (entry.children.length >= 1) {
                entry.children.forEach(function (e) {
                    if (!data.hasOwnProperty("children")) {
                        data.children = [];
                    }
                    data.children.push(_self._convert_entry(e, parent_archive));
                });
            }

            return data;
        }
    }, {
        key: "_reset_stats",
        value: function _reset_stats() {
            this.stats = {
                duplicates: 0,
                files: 0,
                containers: 0,
                directories: 0,
                executables: 0,
                urls: 0
            };
        }

        /**
         * Programtically toggles the highlight of a jstree item
         * @param {Object} [obj] - A jQuery object of a `a.jstree-grid.col-0` selector
         * @param {String} [file_category] - "files", "containers", "exec"
         * @param {Boolean} [highlight] - Whether to highlight or not
         */

    }, {
        key: "selected",
        value: function selected() {
            var files = [];
            $(this.sel_target).jstree("get_checked", true, true).forEach(function (e) {
                if (!e.a_attr.hasOwnProperty("filetree_type") || e.a_attr.filetree_type == "directory") {
                    return true;
                }

                files.push({
                    "filepath": e.a_attr.filepath,
                    "filename": e.text,
                    "sha256": e.a_attr.sha256,
                    "type": e.a_attr.type,
                    "package": e.a_attr.package
                });
            });

            return files;
        }
    }, {
        key: "simplify",
        value: function simplify(state) {
            this._filters.simplify_mime = state;
            this._filters.simplify_sizes = state;
            this._filters.simplify_magic = state;

            this.refresh();
        }
    }, {
        key: "duplicates",
        value: function duplicates(state) {
            this._filters.deselect_duplicates = state;
            this.refresh();
        }
    }], [{
        key: "highlight",
        value: function highlight(obj, file_category, _highlight) {
            var item_type = obj.attr("filetree_type");
            var item_dup = obj.attr("filetree_duplicate");

            if (file_category == "files") {
                if (item_type != "directory") {
                    if (_highlight) obj.addClass("highlight");else obj.removeClass("highlight");
                }
            } else if (file_category == "exec") {
                if (item_type == "exec") {
                    if (_highlight) obj.addClass("highlight");else obj.removeClass("highlight");
                }
            } else if (file_category == "containers") {
                if (item_type == "container" || item_type == "office") {
                    if (_highlight) obj.addClass("highlight");else obj.removeClass("highlight");
                }
            } else if (file_category == "duplicates") {
                if (item_dup == "true") {
                    if (_highlight) obj.addClass("highlight");else obj.removeClass("highlight");
                }
            } else if (file_category == "urls") {
                if (item_type == "url") {
                    if (_highlight) obj.addClass("highlight");else obj.removeClass("highlight");
                }
            }
        }
    }]);

    return FileTree;
}();
//# sourceMappingURL=filetree.js.map
