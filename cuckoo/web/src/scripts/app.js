/*
 * Copyright (C) 2010-2013 Claudio Guarnieri.
 * Copyright (C) 2014-2016 Cuckoo Foundation.
 * This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
 * See the file 'docs/LICENSE' for copying permission.
 *
 */

/**
 * CuckooWeb miscellaneous functions class.
 */
class CuckooWeb {
    // mpen @ http://stackoverflow.com/a/14919494/2054778
    static human_size(bytes, si){
        var thresh = si ? 1000 : 1024;
        if(Math.abs(bytes) < thresh) {
            return bytes + ' B';
        }
        var units = si
            ? ['kB','MB','GB','TB','PB','EB','ZB','YB']
            : ['KiB','MiB','GiB','TiB','PiB','EiB','ZiB','YiB'];
        var u = -1;
        do {
            bytes /= thresh;
            ++u;
        } while(Math.abs(bytes) >= thresh && u < units.length - 1);
        return bytes.toFixed(1)+' '+units[u];
    }

    static api_post(url, params, callback, errback, beforesend){
        
        let data = JSON.stringify(params);

        $.ajax({
            type: "post",
            contentType: "application/json",
            url: url,
            dataType: "json",
            data: data,
            timeout: 20000,
            beforeSend: function(){
                if(beforesend){
                    beforesend()
                }
            },
            success: function(data){
                if(callback) {
                    callback(data);
                }
            }
        }).fail(function(err){

            if(err.hasOwnProperty("responseJSON") && err.responseJSON.hasOwnProperty("message")){
                console.log(`POST err: ${err.responseJSON.message}`);
            } else {
                console.log(`POST err: ${err}`);
            }

            if(errback) {
                errback(err);
            }
        });
    }

    static getFormattedDate(jsondate) {
        var date = new Date(jsondate);

        var month = date.getMonth() + 1;
        var day = date.getDate();
        var hour = date.getHours();
        var min = date.getMinutes();
        var sec = date.getSeconds();

        month = (month < 10 ? "0" : "") + month;
        day = (day < 10 ? "0" : "") + day;
        hour = (hour < 10 ? "0" : "") + hour;
        min = (min < 10 ? "0" : "") + min;
        sec = (sec < 10 ? "0" : "") + sec;

        return date.getFullYear() + "-" + month + "-" + day + " " +  hour + ":" + min;
    }

    static redirect(location){
        window.location.href = location;
    }

    static toggle_page_freeze(open, text) {

        if(open) {
            $('.page-freeze__message').text(text);
            $('.page-freeze').addClass('in');
        } else {
            $('.page-freeze').removeClass('in');
            $('.page-freeze__options').addClass('hidden');
        }
    }

    static error_page_freeze(text) {
        $('.page-freeze').addClass('error');
        $('.page-freeze__message').text(text);
        $('.page-freeze__options').removeClass('hidden');
    }

}

/*
    class PageSwitcher
    - a class that handles 'tabbed' navigation
    - primarily [now] used at the network analysis page as proof of concept
    - this class will be traversible and highly configurable using hooks (will improve overall page performance)
    - this technique might open a few windows on asynchronous page loading, which I will highly recommend for this page
    - also in mind to do this all using Handlebars, which works overall nice with these kind of pages, but that'll 
      require some back-end logistics for getting its required data. but this needs to be discussed at some point.
      Overall thing is: This page is excrumentially slow, due to ALL the data that is present in the html on load of this
      page, which makes it perform really bad. See webconsole's Profile Check for a lookup.
    - For now I'll try what I can do to optimize this page by de-initializing modules that are not visible.
 */
class PageSwitcher {

    constructor(options) {
        this.nav = options.nav;
        this.container = options.container;

        this.pages = [];

        this.events = $.extend({
            transition: function(){},
            beforeTransition: function(){},
            afterTransition: function(){}
        }, options.events ? options.events : {});

        this.initialise();
    }

    /*
        Called on instance construction
     */
    initialise() {

        var _this = this;

        this.indexPages();

        this.nav.find('a').bind('click', function(e) {
            e.preventDefault();
            _this._beforeTransition($(this));
        });

    }

    /*
        Creates a short summary about the pages and their names
     */
    indexPages() {
        var _this = this;
        this.container.children('div').each(function() {
            _this.pages.push({
                name: $(this).attr('id'),
                el: $(this),
                initialised: false
            });
        });
    }

    /*
        Prepares a transition
        - a transition is traversing from page A to page B
     */
    _beforeTransition(el) {

        var name = el.attr('href').replace('#','');
        var targetPage;

        if(this.exists(name)) {
            this.nav.find('a').removeClass('active');
            this.container.children('div').removeClass('active');

            targetPage = this.getPage(name);

            this.events.beforeTransition.apply(this, [name, targetPage]);
            this._transition(targetPage, el);
        } else {
            this._afterTransition();
        }

    }

    /*
        Executes the transition
     */
    _transition(page, link) {
        page.el.addClass('active');
        link.addClass('active');
        this.events.transition.apply(this, [page, link]);
        this._afterTransition(page);
    }

    /*
        Finishes the transition
     */
    _afterTransition(page) {
        this.events.afterTransition.apply(this, [page]);
    }

    /*
        returns a page by name
     */
    getPage(name) {
        return this.pages.filter(function(element) {
            return element.name == name;
        })[0];
    }

    /*
        quick-validates if a page exists
     */
    exists(name) {
        return this.getPage(name) !== undefined;
    }

    /*
        public method for transitioning programatically
     */
    transition(name) { 
        if(this.exists(name)) {
            this._beforeTransition(this.nav.children(`[href=${name}]`));
        } else {
            return false;
        }
    }

}

$(document).ready(function() {
    $("[data-toggle=popover]").popover();

    $('.close-page-freeze').bind('click', function() {
        CuckooWeb.toggle_page_freeze(false);
        setTimeout(function() {
            $('.page-freeze').removeClass('error');
        }, 300);
    });

});

// show/hide errors
$(function() {

    var $container = $('.cuckoo-errors');
    var $errors = $container.find('.errors');
    var $toggle = $container.find('.show-all-errors a');
    var $errorExpand = $container.find('.expand-error');
    var expanded = false;
    var maxErrors = 3;

    // 1. collapse and expand individual errors
    $(".cuckoo-errors .expand-error").bind('click', function(e) {

        e.preventDefault();

        if($(this).parent().hasClass('expanded')) {
            $(this).attr('title', 'Expand error message');
            $(this).parent().removeClass('expanded');
        } else {
            $(this).attr('title', 'Collapse error message');
            $(this).parent().addClass('expanded');
        }

    });

    // 2. show or hide ALL errors
    $toggle.bind('click', function(e) {

        e.preventDefault();

        if(expanded) {
            expanded = false;
        } else {
            expanded = true;
        }

    });

});

// back-to-top replacement for the analysis pages
$(function() {
    $("#analysis .flex-grid__footer .logo a").bind('click', function(e) {
        e.preventDefault();
        $(this).parents('.flex-nav__body').scrollTop(0);
    });
});

// primary navigation things
$(function() {

    function theme_switch(theme) {
        Cookies("theme", theme, {expires: 365 * 10});
        $('body').removeClass('cyborg night');
        $('body').addClass(theme);
        $(".app-nav__dropdown").removeClass('in');
    }

    $("#select-theme").bind('click', function(e) {
        e.preventDefault();
        $(this).parent().find('.app-nav__dropdown').toggleClass('in');
    });

    $(".theme-selection a").bind('click', function(e) { 
        e.preventDefault();
        // set active class
        $(".theme-selection a").removeClass('active');
        $(this).addClass('active');
        // toggle theme
        var theme = $(this).attr("href").split(':')[1];
        // if(theme == 'default') theme ='';
        theme_switch(theme);
    });

    // close the theme dropdown on body click
    $('body').bind('click', function(e) {
        if($(e.target).parents('.app-nav__dropdown--parent').length == 0) {
            $(".app-nav__dropdown").removeClass('in');
        }
    });

});

// utility class for controlling the dashboard
// table views
class DashboardTable {

    // constructs the dashboardtable class
    constructor(el, options) {

        this.options = $.extend({
            limit: 3,
            afterLoad: function() {},
            afterRender: function() {}
        }, options);

        this.el = el;
        this.limitSelect = this.el.find('[data-select="limit"]');

        this.initialise();

    }

    initialise() {

        var _this = this;

        this.limitSelect.bind('change', function() {
            var value = $(this).val();
            _this.changeLimit(value);
        });

        this.load();

    }

    changeLimit(val) {
        this.options.limit = val;
        this.load();
    }

    load() {

        var _this = this;
        var limit = parseInt(this.options.limit);

        $.ajax({
            type: "POST",
            url: "/analysis/api/tasks/recent/",
            contentType: "application/json",
            dataType: "json",
            data: JSON.stringify({
                cats: [],
                limit: isNaN(limit) ? 3 : limit,
                offset: 0,
                packs: [],
                score: ""
            }),
            success: function(response) {

            	if(response.tasks && $.isArray(response.tasks)) {

            		response = response.tasks.map(function(item) {
	                    if(item.added_on) item.added_on = moment(item.added_on).format('DD/MM/YYYY');
	                    return item;
	                });

            	} else {

            		response = [];

            	}

                _this.afterLoad(response);
            }
        });

    }

    afterLoad(data) {

        var limit = parseInt(this.options.limit);

        var completed_table = this.generateTable(data.filter(function(item) {
            return item.status === 'reported';
        }).slice(0,limit));

        var pending_table = this.generateTable(data.filter(function(item) {
            return item.status === 'pending';
        }).slice(0,limit));

        this.el.find("[data-populate='dashboard-table-recent']").html(completed_table);
        this.el.find("[data-populate='dashboard-table-pending']").html(pending_table);

        this.options.afterRender({
            $recent: this.el.find("[data-populate='dashboard-table-recent']"),
            $pending: this.el.find("[data-populate='dashboard-table-pending']")
        });

    }

    generateTable(data) {

        var limit = this.options.limit;

        return HANDLEBARS_TEMPLATES['dashboard-table']({
            entries: data,
            lessEntries: (data.length < limit)
        });

    }

    // generates a simple table <tbody> output
    // following an object
    static simpleTable(keys) {

        var rows = $('<div />');

        for(var key in keys) {
            var val = keys[key];
            var $tr = $("<tr />");
            $tr.append(`<td>${key}</td>`);
            $tr.append(`<td>${val}</td>`);
            rows.append($tr);
        }

        return rows.html();

    }

}

// dashboard code - gets replaced later into a seperate file
$(function() {

    /* ====================
    CHART
    ==================== */

    // disable nasty iframes from Chart (?)
    Chart.defaults.global.responsive = false;

    function createChart(data) {

        var chart,
            chartCanvas = $('.free-disk-space__chart > canvas')[0],
            ds_total = data.total,
            ds_free = data.free,
            ds_used = data.used,
            percent_free = 100 / ds_total * ds_free,
            percent_used = 100 / ds_total * ds_used,
            human_free = CuckooWeb.human_size(ds_free),
            human_total = CuckooWeb.human_size(ds_total);

        if(chartCanvas) {

            chart = new Chart(chartCanvas, {
                type: 'doughnut',
                data: {
                    labels: [
                        "Free",
                        "Used"
                    ],
                    datasets: [
                        {
                            data: [percent_free, percent_used], // <== this has to come somewhere from a script
                            backgroundColor: [
                                "#52B3D9",
                                "#BE234A"
                            ]
                        }
                    ]
                },
                options: {
                    cutoutPercentage: 70,
                    legend: { 
                        // we use a custom legend featuring more awesomeness
                        display: false 
                    },
                    tooltips: { 
                        // tooltips are for 1996
                        enabled: false 
                    }
                }
            });

        }

        return {
            free: human_free,
            total: human_total
        }

    }

    /* ====================
    OMNI-UPLOADER - uses DnDUpload
    ==================== */
    if($(".omni-uploader").length && window.DnDUpload) {

        // submit uploader
        var submit_uploader = new DnDUpload.Uploader({
            target: 'div#dashboard-submit',
            endpoint: '/submit/api/presubmit/',
            template: HANDLEBARS_TEMPLATES['dndupload_simple'],
            ajax: true,
            templateData: {
                title: 'Submit a file for Analysis',
                html: `<i class="fa fa-upload"></i>\n${$("#analysis_token").html()}`
            },
            dragstart: function(uploader, holder) {
                $(holder).removeClass('dropped');
                $(holder).addClass('dragging');
            },
            dragend: function(uploader, holder) {
                $(holder).removeClass('dragging');
            },
            drop: function(uploader, holder) {
                $(holder).addClass('dropped');
            },
            success: function(data, holder) {
                setTimeout(function() {
                    window.location.href = data.responseURL;
                }, 1000);
            },
            change: function(uploader, holder) {
                $(holder).addClass('dropped');
            }
        });

        submit_uploader.draw(); 

        // import uploader
        var import_uploader = new DnDUpload.Uploader({
            target: 'div#dashboard-import',
            endpoint: '',
            template: HANDLEBARS_TEMPLATES['dndupload_simple'],

            // disables ajax functionality
            ajax: false,

            templateData: {
                title: 'Submit a file to import',
                html: `<i class="fa fa-upload"></i>\n${$('#import_token').html()}\n<input type="hidden" name="category" type="text" value="file">\n`,
                // sets form action for submitting the files to (form action=".. etc")
                formAction: '/analysis/import/',
                inputName: 'analyses'
            },
            dragstart: function(uploader, holder) {
                $(holder).removeClass('dropped');
                $(holder).addClass('dragging');
            },
            dragend: function(uploader, holder) {
                $(holder).removeClass('dragging');
            },
            drop: function(uploader, holder) {
                $(holder).addClass('dropped');
            },
            success: function(data, holder) {
                setTimeout(function() {
                    window.location.href = data.responseURL;
                }, 1000);
            },
            change: function(uploader, holder, files) {
                $(holder).addClass('dropped');
            }
        });

        import_uploader.draw();

    }

    // dashboard components
    if($("#cuckoo-dashboard").length) {

        var dashboard_table = new DashboardTable($("#dashboard-tables"), {
            limit: 3,
            limitOptions: [1,2,3,5,10,20,50,100],

            afterRender: function(elements) {

                elements.$recent.find('tr:not(.less-entries)').addClass('clickable');

                elements.$recent.find('tr:not(.less-entries)').bind('click', function(e) {
                    var id = $(this).find('td:first-child').text();
                    window.location = `/analysis/${id}/summary/`;
                });

            }
        });

        // // retrieve general info about cuckoo
        $.get('/cuckoo/api/status', function(data) {

            // populate tasks information
            var tasks_info = DashboardTable.simpleTable(data.data.tasks);
            $('[data-populate="statistics"]').html(tasks_info);

            // populate free disk space unit
            var disk_space = createChart(data.data.diskspace.analyses);
            $('[data-populate="free-disk-space"]').text(disk_space.free);
            $('[data-populate="total-disk-space"]').text(disk_space.total);

        });


    }

    // default page switcher init
    $(".page-switcher").each(function() {

        var switcher = new PageSwitcher({
            nav: $(this).find('.page-switcher__nav'),
            container: $(this).find('.page-switcher__pages')
        });

    });

});

// focus fix on analysis page
$(function() {

    if($("body#analysis").length) {
        $(".cuckoo-analysis").focus();
        $("#analysis-nav, #primary-nav").bind('click', function() {
            $(".cuckoo-analysis").focus();            
        });
    }

});

function alertbox(msg, context, attr_id){
    if(context) { context = `alert-${context}`; }
    if(attr_id) { attr_id = `id="${attr_id}"`; }
    return `<div ${attr_id} class="alert ${context} signature">${msg}</div>`;
}

String.prototype.capitalize = function() {
    return this.charAt(0).toUpperCase() + this.slice(1);
};