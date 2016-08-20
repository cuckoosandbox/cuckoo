class FileTree {
    constructor(target, convert_data) {
        this.sel_target = target;
        this.data = null;
        this._convert_data = convert_data;

        this._jstree = null;
        this._filters = {
            simplify_mime: true,
            simplify_magic: true,
            simplify_sizes: true,
            deselect_duplicates: true
        };

        this.info = {
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
    draw(data, callback){
        if (!this.sel_target) throw "drawtarget needed";
        this.data = data;

        this.init();
        callback();
    }

    _convert_entry(entry){
        let _self = this;

        // Temporary object
        let obj = {
            filepath: entry.filepath,
            filename: entry.filename,
            type: entry.type,
            state: false, // pre-selected tree item
            size: entry.size,
            duplicate: entry.duplicate,
            opened: false
        };

        if(obj.type != "directory"){
            obj.magic = entry.finger.magic;
            obj.mime = entry.finger.mime;
        }

        // Sanitize object properties
        if(obj.magic){
            if(obj.magic.length >= 170){ obj.magic = `${obj.magic.substring(0, 170)}...`; }
        } else {
            obj.magic = "empty";
        }

        [".exe", ".pdf", ".vbs", ".vba", ".bat", ".py", ".pyc", ".pl", ".rb", "js", ".jse"].forEach(function (x) {
            if (obj.filepath.endsWith(x)) {
                obj.type = "exec";
                obj.state = true;

                _self.info.executables += 1;
            }
        });

        [".doc", ".docx", ".docm", ".dotx", ".dotm", ".docb", ".xltm", ".xls", ".xltx", ".xlsm", ".xlsx", ".xlt", ".ppt", ".pps", ".pot"].forEach(function (x) {
            if (obj.filepath.endsWith(x)) {
                obj.type = "office";
                obj.state = true;

                _self.info.executables += 1;
            }
        });

        // Build JSTree JSON object
        let data = {
            text: obj.filename,
            data: {},
            a_attr: {}
        };

        if(obj.duplicate) {
            obj.type = "duplicate";
            obj.state = false;
            data.a_attr.filetree_duplicate = "true";

            _self.info.duplicates += 1;
        }

        if(obj.type == "directory"){
            obj.opened = true;
            _self.info.directories += 1;
        } else if (obj.type == "file"){
            _self.info.files += 1;
        }

        if(obj.type != "directory") {
            data.data.mime = obj.mime;
            data.data.size = obj.size;
            data.data.magic = obj.magic;

            if(entry.children.length >= 1) {
                obj.type = "container";
                obj.opened = true;
                _self.info.containers += 1;
            }
        }

        data.a_attr.filetree_type = obj.type;
        data.type = obj.type;
        data.state = {
            selected: obj.state,
            opened: obj.opened
        };
        
        // Recurse for child entries (make jstree leafs)
        if(entry.children.length >= 1){
            entry.children.forEach(function(e){
                if(!data.hasOwnProperty("children")) { data.children = []; }
                data.children.push(_self._convert_entry(e));
            })
        }

        return data;
    }

    /**
     * Init the table
     */
    init(){
        $(this.sel_target).empty();

        let data = this.data;

        // Convert the data from the `sflock` format to jstree JSON data if necessary
        if(this._convert_data){
            var data_tmp = [];
            for (var key in data) {
                if (data.hasOwnProperty(key)) {
                    let converted = this._convert_entry(data[key]);
                    data_tmp.push(converted);
                }
            }

            data = data_tmp;
        }

        $(this.sel_target).jstree({
            core: {
                data: data,
                "multiple" : true,
                "animation" : 0,
                "themes": {
                    "name": "default-dark"
                }
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
                columns: [
                    {width: "auto", header: "File"},
                    {width: "auto", header: "Mime", value: "mime"},
                    {width: "auto", header: "Size", value: "size"},
                    {width: "10px", header: "Magic", value: "magic"}
                ],
                resizable: true
            },
            plugins: ["themes", "types", "checkbox", "grid", "wholerow"]
        })
//        .on("open_node.jstree", function (e, data) {
//            data.instance.set_icon(data.node, "fa fa-file-archive-o");
//        }).on("close_node.jstree", function (e, data) {
//            data.instance.set_icon(data.node, "fa fa-file-archive-o");
//        })
        ;

    }

    /**
     * Programtically toggles the highlight of a jstree item
     * @param {Object} [obj] - A jQuery object of a `a.jstree-grid.col-0` selector
     * @param {String} [file_category] - "files", "containers", "exec"
     * @param {Boolean} [highlight] - Wether to highlight or not
     */
    static highlight(obj, file_category, highlight){
        let item_type = obj.attr("filetree_type");
        let item_dup = obj.attr("filetree_duplicate");

        if(file_category == "files"){
            if(item_type != "directory"){
                if(highlight) obj.addClass("highlight");
                else obj.removeClass("highlight");
            }
        } else if (file_category == "exec"){
            if(item_type == "exec"){
                if(highlight) obj.addClass("highlight");
                else obj.removeClass("highlight");
            }
        } else if (file_category == "containers"){
            if(item_type == "container" || item_type == "office"){
                if(highlight) obj.addClass("highlight");
                else obj.removeClass("highlight");
            }
        } else if (file_category == "duplicates"){
             if(item_dup == "true"){
                if(highlight) obj.addClass("highlight");
                else obj.removeClass("highlight");
            }
        }
    }
}