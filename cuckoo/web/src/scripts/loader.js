class Loader {

    constructor(el, options = {}) {
        this.el = el ? el : $('.loading');
        this.message = '';
        this.loading = false;
        this.options = $.extend({
          animate: false,
          duration: 200
        }, options);
    }

    start(msg) {
        if(msg) this.message = msg;
        this.setText();
        this.loading = true;

        if(this.options.animate) {
          this.el.slideDown(this.options.duration);
        } else {
          this.el.show();
        }
    }

    stop(cb = function() {}) {
        this.clearText();
        this.loading = false;

        if(this.options.animate) {
          this.el.slideUp(this.options.duration, cb);
        } else {
          this.el.hide();
          cb();
        }
    }

    toggle(msg) {
        if(this.loading) {
            this.stop();
        } else {
            this.start(msg);
        }
    }

    setText() {
        this.el.find('.loading-message').text(this.message);
    }

    clearText() {
        this.el.find('.loading-message').text('');
    }

}
