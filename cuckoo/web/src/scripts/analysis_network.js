/*
	new HTTP layout helper
 */
class RequestDisplay {

    constructor(el) {
    	// element
        this.el = el;

        // flags
        this.isLoading = false;
        this.isLoaded = false;
        this.isOpen = false;

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
    	}, 5000);
    }

    /*
		called by the load function when it ends, will process 
		the response and start opening the panel.
     */
    loadFinish(response, summaryElement) {

    	this.isLoading = false;
    	this.isLoaded = true;
    	this.el.removeClass('is-loading');
    	summaryElement.find('.fa-chevron-right').removeClass('fa-spinner fa-spin');

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
    	var rd = new RequestDisplay($(this));
	});

});
