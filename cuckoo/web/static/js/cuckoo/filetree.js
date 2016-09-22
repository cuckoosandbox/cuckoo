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
            executables: 0
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
                        converted = this._convert_entry(data[key]);
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

            // Temporary object
            var obj = {
                filepath: entry.filepath,
                filename: entry.filename,
                relapath: entry.relapath,
                extrpath: entry.extrpath,
                type: entry.type,
                state: false, // pre-selected tree item
                size: entry.size,
                duplicate: entry.duplicate,
                opened: false,
                description: entry.description
            };

            if (obj.extrpath) {
                obj.filepath = parent_archive + "/" + obj.extrpath.join("/");
            } else if (!obj.filepath && obj.relapath) {
                obj.filepath = obj.relapath;
            } else if (!obj.relapath) {
                obj.relapath = obj.filepath;
            }

            if (obj.type != "directory") {
                // simplify filters
                if (this._filters.simplify_magic) {
                    obj.magic = entry.finger.magic_human;
                } else {
                    obj.magic = entry.finger.magic;
                }

                if (this._filters.simplify_mime) {
                    obj.mime = entry.finger.mime_human;
                } else {
                    obj.mime = entry.finger.mime;
                }

                if (this._filters.simplify_sizes) {
                    obj.size = CuckooWeb.human_size(obj.size, true);
                }

                // Sanitize object properties
                if (obj.magic) {
                    if (obj.magic.length >= 170) {
                        obj.magic = obj.magic.substring(0, 170) + "...";
                    }
                } else {
                    obj.magic = "empty";
                }

                [".exe", ".pdf", ".vbs", ".vba", ".bat", ".py", ".pyc", ".pl", ".rb", ".js", ".jse"].forEach(function (x) {
                    if (obj.filepath.endsWith(x)) {
                        obj.type = "exec";

                        _self.stats.executables += 1;
                    }
                });

                [".doc", ".docx", ".docm", ".dotx", ".dotm", ".docb", ".xltm", ".xls", ".xltx", ".xlsm", ".xlsx", ".xlt", ".ppt", ".pps", ".pot"].forEach(function (x) {
                    if (obj.filepath.endsWith(x)) {
                        obj.type = "office";

                        _self.stats.executables += 1;
                    }
                });

                if (entry.selected) {
                    obj.state = true;
                    _self.stats.executables += 1;
                }
            }

            // Build JSTree JSON return object
            var data = {
                text: obj.filename,
                data: {},
                a_attr: {}
            };

            data.a_attr.filepath = obj.extrpath.unshift(parent_archive) ? obj.extrpath : [obj.filepath];

            if (obj.duplicate) {
                obj.type = "duplicate";

                // Deselect duplicate file entries depending on the filter settings
                if (this._filters.deselect_duplicates) {
                    obj.state = false;
                }

                // Set class for CSS
                data.a_attr.filetree_duplicate = "true";

                // Update stats
                _self.stats.duplicates += 1;
            }

            if (entry.hasOwnProperty("package")) {
                data.data.package = entry.package;
                data.a_attr.package = entry.package;
            }

            if (obj.type == "directory") {
                obj.opened = true;
                obj.type = "directory";
                _self.stats.directories += 1;
            } else {
                data.data.mime = obj.mime;
                data.data.size = obj.size;
                data.data.magic = obj.magic;

                _self.stats.files += 1;

                if (entry.children.length >= 1) {
                    obj.type = "container";
                    obj.opened = true;
                    _self.stats.containers += 1;
                }
            }

            data.a_attr.filetree_type = obj.type;
            data.type = obj.type;
            data.state = {
                selected: obj.state,
                opened: obj.opened
            };

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
                executables: 0
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
                    "package": e.a_attr.package,
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
            }
        }
    }]);

    return FileTree;
}();

//# sourceMappingURL=filetree.js.map