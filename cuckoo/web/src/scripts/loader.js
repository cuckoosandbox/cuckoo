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

    stop() {
        this.clearText();
        this.loading = false;

        if(this.options.animate) {
          this.el.slideUp(this.options.duration);
        } else {
          this.el.hide();
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
