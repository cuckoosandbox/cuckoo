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
        if (!entry.hasOwnProperty("file")) { return; }
        let _self = this;
        
        let file_obj = entry["file"];

        let filename = file_obj["filepath"];
        let type = "file";
        let selected_state = false;

        // perhaps move the 'type' checking to back-end - endswith is not reliable, use libmagic
        [".zip", ".rar", ".tar", ".tar.gz", "bz2"].forEach(function (x) {
            if (filename.endsWith(x)) type = "archive"
        });

        [".exe", ".pdf", ".vbs", ".vba", ".bat", ".py", ".pyc", ".pl", ".rb"].forEach(function (x) {
            if (filename.endsWith(x)) {
                type = "exec";
                selected_state = true;
            }
        });

        [".doc", ".docx", ".docm", ".dotx", ".dotm", ".docb", ".xltm", ".xls", ".xltx", ".xlsm", ".xlsx", ".xlt", ".ppt", ".pps", ".pot"].forEach(function (x) {
            if (filename.endsWith(x)) {
                type = "office";
                selected_state = true;
            }
        });

        let data = {
            "text": filename,
            "type": type,
            "state": {"selected": selected_state},
            "data": {
                "mime": file_obj["mime"],
                "size": file_obj["size"],
                "magic": `${file_obj["magic"].substring(0, 70)}...`
            }
        };

        if(entry.hasOwnProperty("unpacked")) {
            entry["unpacked"].forEach(function(e){
                if(!data.hasOwnProperty("children")) { data["children"] = []; }

                data["children"].push(_self._convert_entry(e));
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
                    {width: 'auto', header: 'Magic', value: 'magic'},
                ],
                resizable: false
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