class Loader {

    constructor(el) {
        this.el = el ? el : $('.loading');
        this.message = '';
        this.loading = false;
    }

    start(msg) {
        if(msg) this.message = msg;
        this.setText();
        this.loading = true;
        this.el.show();
    }

    stop() {
        this.clearText();
        this.loading = false;
        this.el.hide();
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