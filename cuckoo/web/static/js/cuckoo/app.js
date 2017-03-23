'use strict';

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

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
var CuckooWeb = function () {
    function CuckooWeb() {
        _classCallCheck(this, CuckooWeb);
    }

    _createClass(CuckooWeb, null, [{
        key: 'human_size',

        // mpen @ http://stackoverflow.com/a/14919494/2054778
        value: function human_size(bytes, si) {
            var thresh = si ? 1000 : 1024;
            if (Math.abs(bytes) < thresh) {
                return bytes + ' B';
            }
            var units = si ? ['kB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB'] : ['KiB', 'MiB', 'GiB', 'TiB', 'PiB', 'EiB', 'ZiB', 'YiB'];
            var u = -1;
            do {
                bytes /= thresh;
                ++u;
            } while (Math.abs(bytes) >= thresh && u < units.length - 1);
            return bytes.toFixed(1) + ' ' + units[u];
        }
    }, {
        key: 'api_post',
        value: function api_post(url, params, callback, errback, beforesend) {

            var data = JSON.stringify(params);

            $.ajax({
                type: "post",
                contentType: "application/json",
                url: url,
                dataType: "json",
                data: data,
                timeout: 20000,
                beforeSend: function beforeSend() {
                    if (beforesend) {
                        beforesend();
                    }
                },
                success: function success(data) {
                    if (callback) {
                        callback(data);
                    }
                }
            }).fail(function (err) {

                if (err.hasOwnProperty("responseJSON") && err.responseJSON.hasOwnProperty("message")) {
                    console.log('POST err: ' + err.responseJSON.message);
                } else {
                    console.log('POST err: ' + err);
                }

                if (errback) {
                    errback(err);
                }
            });
        }
    }, {
        key: 'getFormattedDate',
        value: function getFormattedDate(jsondate) {
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

            return date.getFullYear() + "-" + month + "-" + day + " " + hour + ":" + min;
        }
    }, {
        key: 'redirect',
        value: function redirect(location) {
            window.location.href = location;
        }
    }, {
        key: 'toggle_page_freeze',
        value: function toggle_page_freeze(open, text) {

            if (open) {
                $('.page-freeze__message').text(text);
                $('.page-freeze').addClass('in');
            } else {
                $('.page-freeze').removeClass('in');
                $('.page-freeze__options').addClass('hidden');
            }
        }
    }, {
        key: 'error_page_freeze',
        value: function error_page_freeze(text) {
            $('.page-freeze').addClass('error');
            $('.page-freeze__message').text(text);
            $('.page-freeze__options').removeClass('hidden');
        }
    }]);

    return CuckooWeb;
}();

$(document).ready(function () {
    $("[data-toggle=popover]").popover();

    $('.close-page-freeze').bind('click', function () {
        CuckooWeb.toggle_page_freeze(false);
        setTimeout(function () {
            $('.page-freeze').removeClass('error');
        }, 300);
    });
});

// show/hide errors
$(function () {

    var $container = $('.cuckoo-errors');
    var $errors = $container.find('.errors');
    var $toggle = $container.find('.show-all-errors a');
    var $errorExpand = $container.find('.expand-error');
    var expanded = false;
    var maxErrors = 3;

    // 1. collapse and expand individual errors
    $(".cuckoo-errors .expand-error").bind('click', function (e) {

        e.preventDefault();

        if ($(this).parent().hasClass('expanded')) {
            $(this).attr('title', 'Expand error message');
            $(this).parent().removeClass('expanded');
        } else {
            $(this).attr('title', 'Collapse error message');
            $(this).parent().addClass('expanded');
        }
    });

    // 2. show or hide ALL errors
    $toggle.bind('click', function (e) {

        e.preventDefault();

        if (expanded) {
            expanded = false;
        } else {
            expanded = true;
        }
    });
});

// back-to-top replacement for the analysis pages
$(function () {
    $("#analysis .flex-grid__footer .logo a").bind('click', function (e) {
        e.preventDefault();
        $(this).parents('.flex-nav__body').scrollTop(0);
    });
});

// primary navigation things
$(function () {

    function theme_switch(theme) {
        Cookies("theme", theme, { expires: 365 * 10 });
        $('body').removeClass('cyborg night');
        $('body').addClass(theme);
        $(".app-nav__dropdown").removeClass('in');
    }

    $("#select-theme").bind('click', function (e) {
        e.preventDefault();
        $(this).parent().find('.app-nav__dropdown').toggleClass('in');
    });

    $(".theme-selection a").bind('click', function (e) {
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
    $('body').bind('click', function (e) {
        if ($(e.target).parents('.app-nav__dropdown--parent').length == 0) {
            $(".app-nav__dropdown").removeClass('in');
        }
    });
});

// dashboard code - gets replaced later into a seperate file
$(function () {

    /* ====================
    CHART
    ==================== */

    // disable nasty iframes from Chart (?)
    Chart.defaults.global.responsive = false;

    var chart,
        chartCanvas = $('.free-disk-space__chart > canvas')[0];

    if (chartCanvas) {

        chart = new Chart(chartCanvas, {
            type: 'doughnut',
            data: {
                labels: ["Free", "Used"],
                datasets: [{
                    data: [25, 75], // <== this has to come somewhere from a script
                    backgroundColor: ["#52B3D9", "#BE234A"]
                }]
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

    /* ====================
    OMNI-UPLOADER - uses DnDUpload
    ==================== */
    if ($(".omni-uploader").length && window.DnDUpload) {

        // submit uploader
        var submit_uploader = new DnDUpload.Uploader({
            target: 'div#dashboard-submit',
            endpoint: '/submit/api/presubmit',
            template: HANDLEBARS_TEMPLATES['dndupload_simple'],
            templateData: {
                title: 'Submit a file for Analysis',
                html: '<i class="fa fa-upload"></i>'
            },
            dragstart: function dragstart(uploader, holder) {
                $(holder).removeClass('dropped');
                $(holder).addClass('dragging');
            },
            dragend: function dragend(uploader, holder) {
                $(holder).removeClass('dragging');
            },
            drop: function drop(uploader, holder) {
                $(holder).addClass('dropped');
            },
            success: function success(data, holder) {
                setTimeout(function () {
                    window.location.href = data.responseURL;
                }, 1000);
            },
            change: function change(uploader, holder) {
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
                html: '<i class="fa fa-upload"></i>\n' + $('#import_token').html() + '\n<input type="hidden" name="category" type="text" value="file">\n',
                // sets form action for submitting the files to (form action=".. etc")
                formAction: '/analysis/import/',
                inputName: 'analyses'
            },
            dragstart: function dragstart(uploader, holder) {
                $(holder).removeClass('dropped');
                $(holder).addClass('dragging');
            },
            dragend: function dragend(uploader, holder) {
                $(holder).removeClass('dragging');
            },
            drop: function drop(uploader, holder) {
                $(holder).addClass('dropped');
            },
            success: function success(data, holder) {
                setTimeout(function () {
                    window.location.href = data.responseURL;
                }, 1000);
            },
            change: function change(uploader, holder, files) {
                $(holder).addClass('dropped');
            }
        });

        import_uploader.draw();
    }
});

function alertbox(msg, context, attr_id) {
    if (context) {
        context = 'alert-' + context;
    }
    if (attr_id) {
        attr_id = 'id="' + attr_id + '"';
    }
    return '<div ' + attr_id + ' class="alert ' + context + ' signature">' + msg + '</div>';
}

String.prototype.capitalize = function () {
    return this.charAt(0).toUpperCase() + this.slice(1);
};
//# sourceMappingURL=app.js.map
