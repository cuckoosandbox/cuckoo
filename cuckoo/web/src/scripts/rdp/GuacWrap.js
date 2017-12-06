import Hookable from './Hookable';

class GuacamoleWrapper extends Hookable {

  constructor(props) {
    super();

    // destructure properties

    // api hooks
    this.hooks = {
      connect: [],
      error: []
    }

    // detect Guacamole
    if(!window.Guacamole) {
      console.error('No Guacamole! Did you forget to process the avocados in src/scripts/rdp/guac?');
      return false;
    }

    // properties
    this.display = props.display;
    this.parent = props.client; // 'parent' client wrapper
    this.client = null; // reserved for the Guacamole client (created on connect)

  }

  connect() {

    // create the client
    let guac = this.client = new Guacamole.Client(
      new Guacamole.HTTPTunnel("tunnel/")
    );

    // create the display
    this.display.html(guac.getDisplay().getElement());

    guac.onerror = (error) => {
      this.dispatchHook('error', error);
    }

    guac.connect();
    this.dispatchHook('connect', guac);

  }

}

export default GuacamoleWrapper;
