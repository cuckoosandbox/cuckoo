class FileTree {
    constructor(target, convert_data) {
        this.sel_target = target;
        this.data = null;
        this._convert_data = convert_data;

        this._jstree = null;
    }

    /**
     * Draws the table
     */
    draw(data){
        if (!this.sel_target) throw "drawtarget needed";
        this.data = data;

        this.init();
    }

    _convert_entry(entry){
        let _self = this;

        // container
        let obj = {
            filepath: entry.filepath,
            filename: entry.filename,
            type: entry.type,
            state: false, // pre-selected tree item
            magic: entry.magic,
            size: entry.size,
            mime: entry.mime
        };

        // sanatize object properties
        if(obj.magic){
            if(obj.magic.length >= 170){ obj.magic = `${obj.magic.substring(0, 170)}...`; }
        } else {
            obj.magic = "empty";
        }

        [".exe", ".pdf", ".vbs", ".vba", ".bat", ".py", ".pyc", ".pl", ".rb", "js", ".jse"].forEach(function (x) {
            if (obj.filepath.endsWith(x)) {
                obj.type = "exec";
                obj.state = true;
            }
        });

        [".doc", ".docx", ".docm", ".dotx", ".dotm", ".docb", ".xltm", ".xls", ".xltx", ".xlsm", ".xlsx", ".xlt", ".ppt", ".pps", ".pot"].forEach(function (x) {
            if (obj.filepath.endsWith(x)) {
                obj.type = "office";
                obj.state = true;
            }
        });

        // build jstree JSON object
        let data = {
            text: obj.filename,
            type: obj.type,
            state: {
                "selected": obj.state
            }
        };

        if(obj.type != "directory") {
            data["data"] = {
                "mime": obj.mime,
                "size": obj.size,
                "magic": obj.magic
            };

            if(entry.children.length >= 1) { data.type = "archive"; }
        }

        // recurse for child entries (make jstree leafs)
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
                    data_tmp.push(this._convert_entry(data[key]));
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
                "archive": {
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
                }
            },
            grid: {
                columns: [
                    {width: 'auto', header: 'File'},
                    {width: 'auto', header: 'Mime', value: 'mime'},
                    {width: 'auto', header: 'Size', value: 'size'},
                    {width: '10px', header: 'Magic', value: 'magic'}
                ],
                resizable: true
            },
            plugins: ["themes", "types", "checkbox", "grid", "wholerow"]
        })
//        .on('open_node.jstree', function (e, data) {
//            data.instance.set_icon(data.node, "fa fa-file-archive-o");
//        }).on('close_node.jstree', function (e, data) {
//            data.instance.set_icon(data.node, "fa fa-file-archive-o");
//        })
        ;

    }
}