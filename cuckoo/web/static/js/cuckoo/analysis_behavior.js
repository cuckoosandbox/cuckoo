/*
 * Copyright (C) 2010-2013 Claudio Guarnieri.
 * Copyright (C) 2014-2016 Cuckoo Foundation.
 * This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
 * See the file 'docs/LICENSE' for copying permission.
 *
 */

// @TO-DO: cleanup jQuery selectors / comment code / trigger loading indicator

class SummaryBehaviorDetail {
    constructor(task_id, pname, pid, category, val) {
        this.task_id = task_id;
        this.pname = pname;
        this.pid = pid;
        this.category = category;
        this.val = val;
        this.limit = 5;
        this.offset = 0;

        this._setup = false;
        this._sel = $(`section#summary div#summary_${ this.category }`);
    }

    start(offset, limit) {
        let params = {
            "task_id": this.task_id,
            "pid": this.pid,
            "watcher": this.val,
            "pname": this.pname
        };

        if (offset != null) params["offset"] = offset;else params["offset"] = this.offset;
        if (limit != null) params["limit"] = limit;else params["limit"] = this.limit;

        let self = this;

        CuckooWeb.api_post("/analysis/api/task/behavior_get_watcher/", params, function (data) {
            self.start_cb(data, self);
        });
    }

    _setup_html(context) {
        let html = `
            <li id="cat_${ context.val }" class="list-group-item">
                <p><b>${ context.val }</b></p>
                <ul id="${ context.val }"></ul>
                <p class="btn_action">
                    <span class="load_more">Load more</span> | <span class="load_all">Load all</span>
                </p>
            </li>`;

        context._sel.find(`ul#${ context.pid }`).append(html);
        context._sel.find(`ul#${ context.pid } #cat_${ context.val } .btn_action .load_more`).click(function () {
            context.more();
        });
        context._sel.find(`ul#${ context.pid } #cat_${ context.val } .btn_action .load_all`).click(function () {
            context.all();
        });

        context._setup = true;
    }

    start_cb(data, context) {
        if (!context._setup) context._setup_html(context);
        let sel = context._sel.find(`ul#${ context.pid } #cat_${ context.val }`);

        if (data["data"].length < context.limit && context.offset != 0) {
            sel.find(".btn_action").html(`<span class="no_results">No more results...</span>`);
        } else if (data["data"].length < context.limit && context.offset == 0) {
            sel.find(".btn_action").hide();
        }

        let html = "";
        data["data"].forEach(function (obj, i) {
            html += `<li>${ obj }</li>`;
        });

        sel.find(`ul#${ context.val }`).append(html);
    }

    /**
     * Lazyloads more list items
     * @return
     */
    more() {
        this.offset += this.limit;
        this.start();
    }

    /**
     * Clears the list and fetches everything
     * @return
     */
    all() {
        SummaryBehaviorDetail.clear_list(this);
        SummaryBehaviorDetail.clear_ctrl_btns(this);

        this.start(0, 0); // fetch all
    }

    /**
     * Clears li items
     * @return
     */
    static clear_list(context) {
        context._sel.find(`ul#${ context.pid } #cat_${ context.val } ul#${ context.val }`).html("");
    }

    /**
     * Clears the buttons
     * @return
     */
    static clear_ctrl_btns(context) {
        context._sel.find(`ul#${ context.pid } #cat_${ context.val } .btn_action`).hide();
    }
}

class SummaryBehaviorController {
    constructor(task_id, pname, pid) {
        this.task_id = task_id;
        this.pname = pname;
        this.pid = pid;
        this.loading = false;

        this.behavioral_details = [];
    }

    start() {
        let params = { "task_id": this.task_id, "pid": this.pid };
        let self = this;

        CuckooWeb.api_post("/analysis/api/task/behavior_get_watchers/", params, function (data) {
            self.start_cb(data, self);
        });
    }

    start_cb(data, context) {
        $.each(data["data"], function (key, val) {
            let category = key;

            let sel = $(`div#summary_${ category }`);
            sel.append(`
                <div class="panel panel-default">
                    <div class="panel-heading"><h3 class="panel-title">${ context.pname } <small>pid: ${ context.pid }</small></h3></div>
                    <ul id="${ context.pid }" class="list-group">
                    </ul>
                </div>`);

            $.each(val, function (i, obj) {
                var behavior_detail = new SummaryBehaviorDetail(context.task_id, context.pname, context.pid, category, obj);
                behavior_detail.start();
                context.behavioral_details.push(behavior_detail);
            });
        });
    }

    static toggle_loading() {
        if (this.loading) {
            $(".loading").hide();
            this.loading = false;
        } else {
            $(".loading").show();
            this.loading = true;
        }
    }
}

//# sourceMappingURL=analysis_behavior.js.map