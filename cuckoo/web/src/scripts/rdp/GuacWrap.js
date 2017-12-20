import Hookable from './Hookable';

class GuacamoleWrapper extends Hookable {

  constructor(props) {
    super();

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
    this._mouse = null;
    this._keyboard = null;

  }

  /*
    GuacamoleWrapper.connect
    - connects to the RDP server
   */
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

    // this.mouse();
    // this.keyboard();

  }

  /*
    GuacamoleWrapper.mouse
    - handles mouse interaction
   */
  mouse(enable = true) {
    if(!this.client) return;

    if(enable) {
      this._mouse = new Guacamole.Mouse(this.client.getDisplay().getElement());
      let sendState = state => this.client.sendMouseState(state);

      // apply sendState function
      this._mouse.onmousemove = (state) => {
        if(this.parent.toolbar.buttons.control.toggled) {
          sendState(state);
        }
      }

    }
  }

  /*
    GuacamoleWrapper.keyboard
    - handles keyboard interaction
   */
  keyboard(enable = true) {

    if(!this.client) return;

    if(enable) {
      this._keyboard = new Guacamole.Keyboard(document);
      this._keyboard.onkeydown = (keysym) => this.client.sendKeyEvent(1, keysym);
      this._keyboard.onkeyup = keysym => this.client.sendKeyEvent(0, keysym);
    } else {
      this._keyboard = null;
    }

  }

}

export default GuacamoleWrapper;
