/*
	new HTTP layout helper
 */
class RequestDisplay {

    constructor(el, options) {
    	// element
        this.el = el;

        // flags
        this.isLoading = false;
        this.isLoaded = false;
        this.isOpen = false;

        // actions
        this.actions = options.actions ? options.actions : {};

        this.initialise();
    }

    initialise() {

    	var _this = this;

    	// bind a click event to the summary bar
    	this.el.find('.network-display__request-summary').bind('click', function(e) {
    		e.preventDefault();

    		// only respond if it's not loading
    		if(_this.isLoading) return;

    		// if we already have the loaded data,
    		// jump straight to opening, else, load
    		// and then open.
    		if(_this.isLoaded) {
    			if(_this.isOpen) {
    				_this.close();
    			} else {
    				_this.open();
    			}
    		} else {
    			_this.load($(this));
    		}
    		
    	});

    }

    /*
		loads the content with ajax
     */
    load(summaryElement) {
    	var _this = this;

    	this.isLoading = true;
    	this.el.addClass('is-loading');
    	summaryElement.find('.fa-chevron-right').addClass('fa-spinner fa-spin');

    	// this will later be replaced by the ajax call getting the content
    	setTimeout(function() {
    		_this.loadFinish({}, summaryElement);
    	}, 1000);
    }

    /*
		called by the load function when it ends, will process 
		the response and start opening the panel.
     */
    loadFinish(response, summaryElement) {

        var self = this;

    	this.isLoading = false;
    	this.isLoaded = true;

    	this.el.removeClass('is-loading');
    	summaryElement.find('.fa-chevron-right').removeClass('fa-spinner fa-spin');

        this.el.find('.flex-tabs__tab .btn').bind('click', function(e) {

            e.preventDefault();
            var keys = $(this).attr('href').split(':');
            var action = keys[0];
            var actionValue = keys[1];

            if(self.actions[action] && typeof self.actions[action] === 'function') {
                self.actions[action](actionValue, self.el);
            }

            $(this).parent().find('.btn').removeClass('active');
            $(this).addClass('active');
        });

    	this.open();
    }

    /*
		Opens the response body and request
		details panel.
     */
    open() {
    	this.el.addClass('is-open');
    	this.isOpen = true;
    }

    /*
		Closes the reponse body and request
		details panel.
     */
    close() {
    	this.el.removeClass('is-open');
    	this.isOpen = false;
    }

}

$(function() {

	$("#http-requests .network-display__request").each(function() {
    	var rd = new RequestDisplay($(this), {
            actions: {
                display: function(value, $parent) {
                    console.log(value);
                },
                output: function(value, $parent) {
                    
                    console.log($parent);

                    if(value == 'hex') {
                        $parent.find('.tab-mode').show();
                    } else {
                        $parent.find('.tab-mode').hide();
                    }
                },
                mode: function(value, $parent) {

                }
            }
        });
	});

    // page navigation
    $(".network-analysis-groups > a").bind('click', function(e) {
        e.preventDefault();
        $(".network-analysis-groups > a").removeClass('active');
        $(this).addClass('active');

        $('.network-analysis-pages > div').removeClass('active');
        $(`.network-analysis-pages > ${$(this).attr('href')}`).addClass('active');
    });

});
