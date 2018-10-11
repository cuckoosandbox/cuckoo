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
            ? ['KiB','MiB','GiB','TiB','PiB','EiB','ZiB','YiB']
            : ['kB','MB','GB','TB','PB','EB','ZB','YB'];
        var u = -1;
        do {
            bytes /= thresh;
            ++u;
        } while(Math.abs(bytes) >= thresh && u < units.length - 1);
        return bytes.toFixed(1)+' '+units[u];
    }

    static csrf_token() {
        let token = Cookies.get("csrftoken");
        if(!token) {
            // Fallback. Maybe there is a form on the page?
            let field = $("input[name=csrfmiddlewaretoken]");
            if(field && field.val()) {
                token = field.val();
            }
        }
        return token;
    }

    // Wrapper that adds support for CSRF tokens
    static ajax(args) {
        if(args.type !== "get") {
            const token = CuckooWeb.csrf_token();
            if(!token) {
                console.warn("Request to " + args.url + " on page without CSRF token");
            }
            const beforeSend = args.beforeSend;
            args.beforeSend = function(request) {
                if(token)
                    request.setRequestHeader("X-CSRFToken", token);
                if(beforeSend)
                    beforeSend(request);
            }
        }
        return $.ajax(args);
    }

    // Form
    static post(url, data, success) {
        return CuckooWeb.ajax({
            url: url,
            type: "post",
            data: data,
            success: success
        });
    }

    // JSON
    static api_post(url, params, callback, errback, beforesend, silent = true){

        let data = JSON.stringify(params);

        CuckooWeb.ajax({
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

            // if not silent, spit out error details
            if(!silent) {

              // if a responseJSON is sent with an error object, highlight that property
              if(err.responseJSON !== undefined && err.responseJSON.hasOwnProperty("message")){
                if(!silent) {
                  console.log('XHR error RMessage:');
                  console.log(err.responseJSON.message);
                }
              }

              // always display XHR error status
              console.log(`XHR error details: `);
              console.log(err);

              // also try to show xhr status message
              if(err.statusText) {
                console.log(`XHR: StatusText: ${err.statusText}`);
              }

            }

            // if a callback is given, do the callback.
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

    // shorthand for posting urls to /submit because this method
    // is used in multiple contexts (dashboard, submit)
    static submit_url(urls) {

        if (urls == "") {
            return false;
        }

        CuckooWeb.api_post("/submit/api/presubmit", {
            "data": urls,
            "type": "strings"
        }, function (data) {
            CuckooWeb.redirect("/submit/pre/" + data.submit_id);
        }, function (data) {
            console.log("err: " + data);
        });

    }

    // returns true if the client browser is in the
    // recommended browser list.
    static isRecommendedBrowser() {

        var recommended = ['firefox', 'chrome', 'webkit', 'chromium', 'opera'];
        var isRecommended = false;

        for(var recommendation in recommended) {
            if(bowser[recommended[recommendation]]) {
                isRecommended = true;
                break;
            }
        }

        return {
            recommended: isRecommended,
            browser: bowser.name
        };

    }

    // utility code for quickly rendering <code> fields (ie when some code sample is retrieved via ajax)
    static renderCode(code, options) {

        if(!code) return false;
        if(!options) var options = {};

        return HANDLEBARS_TEMPLATES['code']({
            code: code,
            type: options.type || undefined
        });

    }

    // escaping html
    static escapeHTML(string) {

      var entityMap = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;',
        '/': '&#x2F;',
        '`': '&#x60;',
        '=': '&#x3D;'
      };

      return String(string).replace(/[&<>"'`=\/]/g, function (s) {
        return entityMap[s];
      });

    }

    // reverses the above function
    static unescapeHTML(string) {
      // the most amazing solution ever, found at:
      // https://stackoverflow.com/questions/1147359/how-to-decode-html-entities-using-jquery#comment6018122_2419664

      var t = document.createElement('textarea');
      t.innerHTML = string;
      return t.value;

    }

    /*
      Below are a bunch of polyfilled helpers for the JS Fullscreen API. since
      each are quite browser-specific
     */

    // able to use fullscreen (does the user allow it in the browser config)
    static enabledFullscreen() {
      if(document.fullscreenEnabled) {
        return document.fullscreenEnabled;
      } else if(document.webkitFullscreenEnabled) {
        return document.webkitFullscreenEnabled;
      } else if (document.mozFullscreenEnabled) {
        return document.mozFullscreenEnabled;
      } else {
        // ...
        return false;
      }
    }

    static isFullscreen() {
      if(document.fullscreen) {
        return document.fullscreen;
      } else if(document.webkitIsFullScreen) {
        return document.webkitIsFullScreen;
      } else if(document.mozIsFullScreen) {
        return document.mozIsFullScreen;
      } else if(document.msIsFullScreen) {
        return document.msIsFullScreen;
      } else {
        // ...
        return false;
      }
    }

    static exitFullscreen() {
      if(document.exitFullscreen) {
        document.exitFullscreen();
      } else if(document.webkitExitFullscreen) {
        document.webkitExitFullscreen();
      } else if(document.mozExitFullscreen) {
        document.mozExitFullscreen();
      } else if(document.msExitFullscreen) {
        document.msExitFullscreen();
      } else {
        // the message has already been given in the request handler
        return false;
      }
    }

    // shortcuts requestFullscreen as cross-browser as possible
    static requestFullscreen(element) {
      if(CuckooWeb.enabledFullscreen()) {
        if(element.requestFullscreen) {
          element.requestFullscreen();
        } else if(element.webkitRequestFullscreen) {
          element.webkitRequestFullscreen();
        } else if (element.mozRequestFullscreen) {
          element.mozRequestFullscreen();
        } else if (element.msRequestFullscreen) {
          element.msRequestFullscreen();
        } else {
          console.log('Oh noes! you cannot go in fullscreen due to your browser.');
          return false;
        }
      } else {
        console.log('You did not enable fullscreen in your browser config. you cannot use this feature.');
        return false;
      }
    }

    // shortcuts fullscreen event handling
    static onFullscreenChange(handler = function(){}) {
      document.addEventListener('webkitfullscreenchange', handler, false);
      document.addEventListener('fullscreenchange', handler, false);
      document.addEventListener('mozfullscreenchange', handler, false)
      document.addEventListener('msfullscreenchange', handler, false);
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

    default pageswitcher html structure:

    <div class="page-switcher">

        <nav class="page-switcher__nav">
            <a href="page-switcher-page-1" class="active">page 1</a>
            <a href="page-switcher-page-2">page 2</a>
        </nav>

        <div class="page-switcher__pages">
            <div id="page-switcher-page-1" class="active">content for page 1</div>
            <div id="page-switcher-page-2">content for page 2</div>
        </div>

    </div>

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
        this.container.children('div').each(function(i) {
            _this.pages.push({
                index: i,
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

        if(typeof name === 'string') {
            return this.pages.filter(function(element) {
                return element.name == name;
            })[0];
        } else if (typeof name === 'number') {
            return this.pages[name]; // will return a page at index x
        }

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

        if(typeof name === 'number') {
            var name = this.getPage(name).name;
        }

        if(this.exists(name)) {
            this._beforeTransition(this.nav.children(`[href=${name}]`));
        } else {
            return false;
        }
    }

}

$(document).ready(function() {

    // warn the user about a browser recommendation if we are not using
    // a recommended browser.
    var browser_message = $(".app-message[data-message=browser-recommendation]");
    var recommended = CuckooWeb.isRecommendedBrowser();
    if(!recommended.recommended) {
        browser_message.find('.browser').text(recommended.browser);
        if(!window.localStorage.getItem('hide-browser-warning') === true) {
            browser_message.removeClass('hidden');
        }
    }

    // dismiss the error (once)
    browser_message.find('.button[href="#dismiss"]').bind('click', function(e) {
        e.preventDefault();
        browser_message.addClass('hidden');
    });

    // hide the browser error if the user is OK with lacking support
    browser_message.find('.button[href="#hide"]').bind('click', function(e) {
        e.preventDefault();
        window.localStorage.setItem('hide-browser-warning', true);
        browser_message.addClass('hidden');
    });

    // enable popovers (bootstrap)
    $("[data-toggle=popover]").popover();

    // close the page freeze
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

        CuckooWeb.api_post("/analysis/api/tasks/recent/", {
            cats: [],
            limit: isNaN(limit) ? 3 : limit,
            offset: 0,
            packs: [],
            score: ""
        }, function(response) {
            if(response.tasks && $.isArray(response.tasks)) {
                response = response.tasks.map(function(item) {
                    if(item.added_on) item.added_on = moment(item.added_on).format('DD/MM/YYYY');
                        return item;
                    });
            } else {
                response = [];
            }
            _this.afterLoad(response);
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
    CHART - free disk space
    ==================== */

    // disable nasty iframes from Chart (?)
    Chart.defaults.global.responsive = false;

    function createChart(cSelector, data, outputPercent) {

        var chart,
            chartCanvas = cSelector[0],
            ds_total = data.total,
            ds_free = data.free,
            ds_used = data.used,
            percent_free = 100 / ds_total * ds_free,
            percent_used = 100 / ds_total * ds_used,
            nFree = CuckooWeb.human_size(ds_free),
            nTotal = CuckooWeb.human_size(ds_total);

        var freeColor = "#52B3D9";
        var freeDangerColor = "#afb200";
        var usedColor = "#999";
        var totalColor = "#BE234A";

        if(percent_used > 75) {
            freeColor = freeDangerColor;
        }

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
                                freeColor,
                                usedColor
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

        if(outputPercent) {
            nFree = Math.round(percent_free);
            nTotal = 100;
        }

        return {
            free: nFree,
            total: nTotal,
            used: Math.round(percent_used)
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

          // ***
          // cuckoo quickview tables
          // ***
          var tasks_info = DashboardTable.simpleTable(data.data.tasks);
          $('[data-populate="statistics"]').html(tasks_info);

          // ***
          // cuckoo disk space usage chart
          // ***
          if(data.data.diskspace.analyses) {
              // populate free disk space unit
              var disk_space = createChart($("#ds-stat > canvas"), data.data.diskspace.analyses);
              $('[data-populate="free-disk-space"]').text(disk_space.free);
              $('[data-populate="total-disk-space"]').text(disk_space.total);

          } else {
              // show 'no data available' if this data is not available
              $("#ds-stat").addClass('no-data');
          }


          // ***
          // cuckoo cpu usage chart
          // ***
          if(data.data.cpucount) {

              // cpu load calculation mechanism
              var cores = data.data.cpucount;
              var lsum = 0;
              for(var load in data.data.cpuload) {
                  lsum += data.data.cpuload[load];
              }
              var avgload = parseInt(
                  lsum / data.data.cpuload.length * 100 / cores
              );
              $('[data-populate="cpu-load"]').text(`${avgload}%`);
              $('[data-populate="total-cores"]').text(`${cores} cores`);

              // populate cpu load unit
              var cpu_load = createChart($("#cpu-stat > canvas"), {
                  total: cores * 100,
                  used: avgload,
                  free: 100 - avgload,
              });

          } else {
              // show 'no data available' if this data is not available
              $("#cpu-stat").addClass('no-data');
          }

          // ***
          // cuckoo memory usage chart
          // ***
          if(data.data.memtotal) {

              // memory data
              var memoryTotal = data.data.memtotal;
              var memoryAvail = data.data.memavail;

              // create the memory chart
              var memory_chart = createChart($("#memory-stat > canvas"), {
                  total: memoryTotal,
                  used: memoryTotal - memoryAvail,
                  free: memoryAvail
              }, true);

              var memoryTotalSize = CuckooWeb.human_size(memoryTotal * 1000);
              var memoryAvailSize = CuckooWeb.human_size(memoryAvail * 1000);
              var memoryUsedSize = CuckooWeb.human_size((memoryTotal - memoryAvail) * 1000);

              $('[data-populate="memory-used"]').text(`${memoryAvailSize}`);
              $('[data-populate="memory-total"]').text(`${memoryTotalSize}`);

          } else {
              $("#memory-stat").addClass('no-data');
          }

          // ***
          // cuckoo versioning block
          // ***
          let $versionBlock = $("[data-dashboard-module='installation']");

          let vCur = data.data.version;
          let vNew = data.data.latest_version;

          // check existence and compare
          if((vCur && vNew) && (vCur !== vNew)) {
            // go into 'attention - you need to update' mode if we're not on the latest version
            $versionBlock
              .addClass('attention')
              .find('.latest-version td:last-child')
              .text(vNew)
              .parents('tr').show();
          } else {
            // show the 'you are up to date message' when the version is the same
            $versionBlock
              .find('.up-to-date')
              .show();
          }

          $versionBlock.addClass('version-loaded');

          // ***
          // cuckoo recent blogposts block
          // ***
          let $blogBlock = $("[data-dashboard-module='blogposts']");
          let blogTmpl = Handlebars.compile($blogBlock.find('template#blogpost-template').html());
          $blogBlock.find('.dashboard-module__body').html(blogTmpl({ posts: data.data.blogposts }));

        });

        // submit the dashboard url submitter
        $("#submit-with-link form").bind('submit', function(e) {
            e.preventDefault();
            var urls = $("#submit-with-link textarea").val();
            CuckooWeb.submit_url(urls);
        });

    }

    // default page switcher init
    $(".page-switcher").each(function() {

        var switcher = new PageSwitcher({
            nav: $(this).find('.page-switcher__nav'),
            container: $(this).find('.page-switcher__pages')
        });

        $(this).data('pageSwitcher', switcher);

    });

});

// analysis page handlers
$(function() {

    // fixes up the scroll behavior to expected behavior
    if($("body#analysis").length) {
        $(".cuckoo-analysis").focus();
        $("#analysis-nav, #primary-nav").bind('click', function() {
            $(".cuckoo-analysis").focus();
        });
    }

    // pre-submits a list of urls to the presubmit form (uses urlhash submission)
    $("#submit-extracted-urls").bind('click', function(e) {
        e.preventDefault();
        var listItems = $(this).parents('.list-panel').find('.list-group-item');
        var urls = [];

        listItems.each(function() {
            urls.push($(this).text());
        });

        urls = urls.join('\n');
        CuckooWeb.submit_url(urls);
    });


    if(window.hljs) {
      // initialise hljs
      hljs.configure({
          languages: ['js']
      });

      hljs.initHighlightingOnLoad();

      $("pre code").each(function(i, element) {
          hljs.highlightBlock(element);
      });
    }

    // retrieving powershell code and displaying it - if it hasn't been loaded yet.
    if($(".extracted-switcher").length) {

        function fetchPowerShell(el) {

            var url = el.find('[data-powershell-source]').attr('data-powershell-source');

            $.get(url).success(function(response) {
                // do make newlines from ; for good overview
                var code = S(response).replaceAll(';',';\n');
                // render code block and inject
                var html = $(CuckooWeb.renderCode(code), {
                    type: 'powershell'
                });

                // initialize hljs on that codeblock
                html.find('code').each(function(i, block) {
                    hljs.highlightBlock(block);
                });

                // inject somewhere after 'el'
                el.find('.powershell-preview').html(html);
                el.addClass('powershell-loaded');

            }).error(function() {

                el.find('.powershell-preview').html('<p class="alert alert-danger">Something went wrong loading the script. Please try again later.</p>')

            });

        }

        var switcher = $(".extracted-switcher").data('pageSwitcher');

        switcher.events.afterTransition = function(page) {
            if(!page.el.hasClass('powershell-loaded')) {
                fetchPowerShell(page.el);
            }
        }

        switcher.transition(0);

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
