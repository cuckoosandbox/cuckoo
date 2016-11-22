/*
 UIKit v1.0
 - AMD wrapper help: http://gomakethings.com/the-anatomy-of-a-vanilla-javascript-plugin/
 */

(function (root, factory) {
    if (typeof define === 'function' && define.amd) {
        define(['UIKit'], factory(root));
    } else if (typeof exports === 'object') {
        module.exports = factory(require('UIKit'));
    } else {
        root.UIKit = factory(root, root.UIKit);
    }
})(typeof global !== 'undefined' ? global : this.window || this.global, function (root) {

    var store = {};

    /*
     Collapsable
     */
    function Collapsable(el, options) {

        if (!options) options = {};

        this.$ = el;
        this.$toggle = this.$.find('.collapse-toggle');
        this.target = this.$.find('[data-target]');

        this.isOpen = false;
        this.options = {
            state: 'closed',
            close: function () {
            },
            open: function () {
            }
        };

        return this.initialise(options);
    }

    Collapsable.prototype = {

        initialise: function (options) {

            var self = this;

            this.$.addClass('collapsable');

            options.state = this.$.data('state');
            this.options = $.extend(this.options, options);

            // binds the listener
            this.$toggle.on('click', function (e) {
                e.preventDefault();
                this.toggle();
            }.bind(this));

            if (this.options.state == 'open') this.open();

            return this;
        },

        open: function () {
            this.isOpen = true;
            this.$.addClass('open');
            this.options.open.bind(this);
        },

        close: function () {
            this.options.open.bind(this);
            this.$.removeClass('open');
            this.isOpen = false;
        },

        toggle: function () {
            if (this.isOpen) {
                this.close();
            } else {
                this.open();
            }
        }

    }

    // TableController
    function TableController(el, options) {

        if (!options) options = {};

        this.$ = el;
        this.$pagination = this.$.find('.table-display-config .pagination');
        this.data = [];

        // pagination things
        this.page = 0;
        this.resultsShown = 10;
        this.totalPages = 0;
        this.isFirst = false;
        this.isLast = false;

        // flag
        this.resultControlsInitialised = false;

        return this.initialise(options);

    }

    TableController.prototype = {

        initialise: function (options) {

            // create stupid table instance, takes care of sorting
            this.parseResults();
            this.initialisePagination();
            this.populate();
            this.$.stupidtable();

            return this;
        },

        initialisePagination: function (cb) {

            var $first, $prev, $last, $next;

            if (this.$pagination.length) {

                // first check if we NEED pagination (less results than our per-page views)
                if (this.data.length < this.resultsShown && !this.isInitialised) {
                    this.$.find('.table-display-config, tfoot').hide();
                    return;
                }

                // removes exisiting li's which arent' one of the handlers
                this.$pagination.find('li[data-page]').remove();

                $first = this.$pagination.find('.first > a');
                $prev = this.$pagination.find('.prev > a');
                $last = this.$pagination.find('.last > a');
                $next = this.$pagination.find('.next > a');

                this.totalPages = Math.round(this.data.length / this.resultsShown);

                // create paginatåable refs

                $set = [];

                for (var p = 0; p < this.totalPages; p++) {
                    var $a = $("<a href='" + p + "'>" + (p + 1) + "</a>");
                    var $li = $("<li />");
                    $li.attr('data-page', p);
                    $li.append($a);
                    $set.push($li);
                }

                // appends new li's in the bar
                this.$pagination.find('.prev').after($set);

                // attaches click handlers
                this.$pagination.find('li[data-page] > a').bind('click', this.handlers.paginateTo.bind(this));

                if (!this.resultControlsInitialised) {
                    $next.bind('click', this.handlers.paginateNext.bind(this));
                    $prev.bind('click', this.handlers.paginatePrev.bind(this));
                    $last.bind('click', this.handlers.paginateLast.bind(this));
                    $first.bind('click', this.handlers.paginateFirst.bind(this));
                    this.initialiseResultControls();
                }

                if (cb) {
                    cb.apply(this);
                }

            }
        },

        initialiseResultControls: function () {

            $results = this.$.find('.results-per-page');
            $input = $results.find('input[name="rpp"]');
            $update = $results.find('[data-action="update-rpp"]');
            $all = $results.find('[data-action="rpp-all"]');

            $input.val(this.resultsShown);
            $update.bind('click', this.handlers.setShownResults.bind(this));
            $all.bind('click', this.handlers.showAllResults.bind(this));

            this.resultControlsInitialised = true;

        },

        // handles toggling and bolding / hiding / showing of pagination stuff
        paginationState: function () {

            // hide next button
            var $backward = this.$pagination.find('.first,.prev');
            var $forward = this.$pagination.find('.last,.next');

            // set last and first flags
            this.isFirst = (this.page == 0);
            this.isLast = (this.page == this.totalPages - 1 ? true : false);

            //
            this.$pagination.find('li[data-page]').removeClass('active');
            this.$pagination.find('li[data-page=' + this.page + ']').addClass('active');

            this.isLast ? $forward.addClass('disabled') : $forward.removeClass('disabled');
            this.isFirst ? $backward.addClass('disabled') : $backward.removeClass('disabled');

        },

        parseResults: function () {
            // ran once by initialise, this fetches all the table content
            // and parses it into a 'data' array. other functions use
            // this set to reconstruct
            var self = this;

            this.$.find('tbody > tr').each(function (i) {
                var resultKey = {};
                resultKey.html = $("<tr />").append($(this).clone()).html();
                resultKey.index = i;
                self.data.push(resultKey);
            });

            this.populate(0);
        },

        getPaginatedDataSet: function (page) {

            if (page) {
                this.page = parseInt(page);
            }

            var currentPosition = this.page * this.resultsShown;
            var toPosition = currentPosition + this.resultsShown;
            var results = this.data.slice(currentPosition, toPosition);

            return results;
        },

        populate: function (page) {

            var set = this.getPaginatedDataSet(page);
            var $tbody = this.$.find('tbody');

            // empties the current tbody element
            $tbody.empty();

            set.forEach(function (item) {
                $tbody.append(item.html);
            });

            // if(set.length < this.resultsShown) {
            // 	// emulate more tr's to maintain height
            // 	// !gives problems with sorting!
            // 	var diff = this.resultsShown - set.length;
            // 	for(var i = 0; i < diff; i++) {
            // 		var $tr = $("<tr />").css('height', $tbody.find('tr:first-child').height());
            // 		$tbody.append($tr);
            // 	}
            // }

            this.paginationState();

        },

        handlers: {
            paginateNext: function (e) {
                if (e) e.preventDefault();
                if (!this.isLast) {
                    this.page += 1;
                    this.populate();
                }
            },
            paginatePrev: function (e) {
                if (e) e.preventDefault();
                if (!this.isFirst) {
                    this.page -= 1;
                    this.populate();
                }
            },
            paginateFirst: function (e) {
                if (e) e.preventDefault();
                this.page = 0;
                this.populate();
            },
            paginateLast: function (e) {
                if (e) e.preventDefault();
                this.page = this.totalPages - 1;
                this.populate();
            },
            paginateTo: function (e) {
                if (e) e.preventDefault();

                if (e.target) {
                    this.page = $(e.target).attr('href');
                } else {
                    var i = parseInt(i);
                    if (!isNaN(i) && i < this.totalPages && i > 0) {
                        this.page = i;
                    }
                }

                this.populate();
            },
            setShownResults: function (e, n) {

                var self = this;

                if (!n) {
                    var $input = $(e.target).parent().find('input[name=rpp]');
                    var value = parseInt($input.val());
                } else {
                    var value = parseInt(n);
                }

                if (!isNaN(value)) {

                    if (value > this.data.length) {
                        value = this.data.length;
                    }

                    this.resultsShown = value;

                    this.initialisePagination(function () {
                        this.page = 0;
                        this.populate();
                        self.$.find('input[name=rpp]').val(this.resultsShown);
                    });

                } else {

                }

            },
            showAllResults: function (e) {
                e.preventDefault();
                var total = this.data.length;
                this.handlers.setShownResults.call(this, null, total);
            }
        }

    }

    // util: register
    function register(key, obj) {
        if (!store[key]) store[key] = [];
        store[key].push(obj);
        return obj;
    }

    return {

        Collapsable: function (_$, options) {
            var c = new Collapsable(_$, options);
            return register('collapsables', c);
        },

        // ResultfilterTable
        TableController: function (_$, options) {
            var t = new TableController(_$, options);
            return register('tablecontrollers', t);
        },

        store: store
    };

});