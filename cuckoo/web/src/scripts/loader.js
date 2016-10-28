class Loader {

    constructor(el) {
        this.el = el ? el : $('.loading');
        this.loading = false;
    }

    start() {
        console.log('start loader');
        this.loading = true;
        this.el.show();
    }

    stop() {
        console.log('stop loader');
        this.loading = false;
        this.el.hide();
    }

    toggle() {
        console.log('toggle loader');
        if(this.loading) {
            this.stop();
        } else {
            this.start();
        }
    }

}