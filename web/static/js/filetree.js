class FileTree {
    constructor(target, data) {
        this.sel_target = target;
        this.data = data;

        this._jstree = null;
        this._drawn = false;
    }

    /**
     * Draws the table
     */
    draw(){
        if (!this.data || !this.sel_target) throw "data & drawtarget needed";
        if (this._drawn){ this._init(); }
    }

    /**
     * Init the table
     */
    init(){
        $(this.sel_target).empty();
        $(this.sel_target).jstree({
            core: {
                data: jsonData,
                "multiple" : true,
                "animation" : 0
            },
            types: {
                "archive": {
                    "icon": "fa fa-file-archive-o"
                },
                "child": {
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
                    {width: 'auto', header: 'Size', value: 'size'}
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

        this._jstree = $.jtree.reference(this.sel_target);

        this._drawn = true;
    }
}