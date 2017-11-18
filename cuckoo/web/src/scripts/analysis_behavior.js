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
        this._sel = $(`section#summary div#summary_${this.category}`);
    }

    start(offset, limit){
        let params = {
            "task_id": this.task_id,
            "pid": this.pid,
            "watcher": this.val,
            "pname": this.pname
        };

        if(offset != null) params["offset"] = offset;
        else params["offset"] = this.offset;
        if(limit != null) params["limit"] = limit;
        else params["limit"] = this.limit;

        let self = this;

        CuckooWeb.api_post("/analysis/api/task/behavior_get_watcher/", params, function(data){ self.start_cb(data, self); });
    }

    _setup_html(context){
        let html = `
            <li id="cat_${context.val}" class="list-group-item">
                <p><b>${context.val}</b></p>
                <ul id="${context.val}"></ul>
                <p class="btn_action">
                    <span class="load_more">Load more</span> | <span class="load_all">Load all</span>
                </p>
            </li>`;

        context._sel.find(`ul#${context.pid}`).append(html);
        context._sel.find(`ul#${context.pid} #cat_${context.val} .btn_action .load_more`).click(function(){ context.more(); });
        context._sel.find(`ul#${context.pid} #cat_${context.val} .btn_action .load_all`).click(function(){ context.all(); });

        context._setup = true;
    }

    start_cb(data, context){
        if(!context._setup) context._setup_html(context);
        let sel = context._sel.find(`ul#${context.pid} #cat_${context.val}`);

        if(data["data"].length < context.limit && context.offset != 0){
            sel.find(".btn_action").html(`<span class="no_results">No more results...</span>`);
        } else if (data["data"].length < context.limit && context.offset == 0){
            sel.find(".btn_action").hide();
        }

        let html = "";
        data["data"].forEach(function(obj, i){
            html += `<li>${obj}</li>`;
        });

        sel.find(`ul#${context.val}`).append(html);
    }

    /**
     * Lazyloads more list items
     * @return
     */
    more(){
        this.offset += this.limit;
        this.start();
    }

    /**
     * Clears the list and fetches everything
     * @return
     */
    all(){
        SummaryBehaviorDetail.clear_list(this);
        SummaryBehaviorDetail.clear_ctrl_btns(this);

        this.start(0,0); // fetch all
    }

    /**
     * Clears li items
     * @return
     */
    static clear_list(context){
        context._sel.find(`ul#${context.pid} #cat_${context.val} ul#${context.val}`).html("");
    }

    /**
     * Clears the buttons
     * @return
     */
    static clear_ctrl_btns(context){
        context._sel.find(`ul#${context.pid} #cat_${context.val} .btn_action`).hide();
    }
}

class SummaryBehaviorController {

    constructor(task_id, pname, pid) {

        this.task_id = task_id;
        this.pname = pname;
        this.pid = pid;
        this.loading = false;
        this.loader = new Loader($(".loading"));

        this.behavioral_details = [];

    }

    start(){
        let params = {"task_id": this.task_id, "pid": this.pid};
        let self = this;

        CuckooWeb.api_post("/analysis/api/task/behavior_get_watchers/", params,
            function(data){ self.start_cb(data, self); });
    }

    start_cb(data, context){
        $.each(data["data"], function(key, val){
            let category = key;

            let sel = $(`div#summary_${category}`);
            sel.append(`
                <div class="panel panel-default">
                    <div class="panel-heading"><h3 class="panel-title">${context.pname} <small>pid: ${context.pid}</small></h3></div>
                    <ul id="${context.pid}" class="list-group">
                    </ul>
                </div>`);

            $.each(val, function(i, obj){
                var behavior_detail = new SummaryBehaviorDetail(context.task_id, context.pname, context.pid, category, obj);
                behavior_detail.start();
                context.behavioral_details.push(behavior_detail)
            });
        });
    }

    static toggle_loading(){
        this.loader.toggle();
    }

}

class SummarySimplifier {

    constructor(el) {
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

    initialise() {

        var _self = this;

        this.el.on('click', function(e) {
            e.preventDefault();
            _self.toggle();
        });

        if($('body').attr('data-simplified') === 'true') {
            this._simplified = true;
            this._update();
        } else {
            this._simplified = false;
            this._update();
        }

        return this;
    }

    toggle() {

        if(this._simplified) {
            this._off();
        } else {
            this._on();
        }

        this._save();

    }

    _off() {
        this._simplified = false;
        this._update();
    }

    _on() {
        this._simplified = true;
        this._update();

        for(var cb in this._callbacks.on)  {
            this._callbacks.on[cb]();
        }
    }

    _update(preset) {

        if(this._simplified) {
            this.el.addClass('active');
            this.el.find('span').text('default overview');
            $('body').attr('data-simplified', "true");
        } else {
            this.el.removeClass('active');
            this.el.find('span').text('simplify overview');
            $('body').attr('data-simplified', 'false');
        }

    }

    _save() {
        Cookies("simplified_view", this._simplified, {expires: 365 * 10});
    }

    // adds 'listener' callbacks, like events
    listen(namespace, fn) {
        this._callbacks[namespace].push(fn);
    }

}

$(function() {

    var simplifier;

    if($("#toggle-simplified").length) {
        simplifier = window.simplifier = new SummarySimplifier($("#toggle-simplified"));
    }

    // since the pew pew won't draw if it's invisible
    if(window.pewpew && typeof window.pewpew === 'function') {
        if(simplifier) {
            if(!simplifier._simplified) {
                simplifier.listen('on', function() {
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
