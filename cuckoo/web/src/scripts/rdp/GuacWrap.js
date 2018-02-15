import Hookable from './Hookable';

class GuacamoleWrapper extends Hookable {

  constructor(props) {
    super();

    // api hooks
    this.hooks = {
      connect: [],
      error: [],
      end: []
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
    let tunnel = new Guacamole.HTTPTunnel("tunnel/");
    let guac = this.client = new Guacamole.Client(tunnel);;

    // create the display
    this.display.html(guac.getDisplay().getElement());

    tunnel.onerror =
    guac.onerror = (error) => {
      // skipping over error codes, for instance: the ending session is
      // also thrown as an error, so taking advantage of the status code to
      // delegate the correct
      switch(error.code) {
        case 523:
        break;
        default:
          this.dispatchHook('error', error);
      }
    }

    tunnel.onstatechange = (state) => {
      if(state == 2) {
        this.dispatchHook('ended');
      }
    }

    guac.connect();
    this.dispatchHook('connect', guac);

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
      this._mouse.onmousemove =
      this._mouse.onmouseup =
      this._mouse.onmousedown = (state) => {
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
      this._keyboard.onkeydown = (keysym) => {
        if(this.parent.toolbar.buttons.control.toggled) {
          this.client.sendKeyEvent(1, keysym);
        }
      }
      this._keyboard.onkeyup = keysym => {
        if(this.parent.toolbar.buttons.control.toggled) {
          this.client.sendKeyEvent(0, keysym);
        }
      }
    } else {
      this._keyboard = null;
    }

  }

  /*
    GuacamoleWrapper.getCanvas
    - shortcut for returning default guac layer (active tunnel viewport)
   */
  getCanvas() {
    if(this.client) {
      return this.client.getDisplay().getDefaultLayer().getCanvas();
    }
    return false;
  }

  /*
    GuacamoleWrapper.checkReady

    - polls to /info api call for checking if the task did finish
    - example:

      // poll
      client.checkReady(1, true, 'completed').then(ready => {
        if(ready) {
          console.log('vm is ready');
        } else {
          console.log('vm is not ready');
        }
      });

    - ID                = Number
    - poll              = true|false
    - pollUntillStatus  = "completed|reported"

    - returns: [ready{Bool},]

   */
  checkReady(id, poll = false, pollUntillStatus = 'completed') {

    let iv = null;

    // the verification call as a promise
    let readyCall = () => new Promise((resolve, reject) => {

      try {

        $.ajax({
          url: '/analysis/api/tasks/info/',
          type: 'POST',
          dataType: 'json',
          contentType: "application/json; charset=utf-8",
          data: JSON.stringify({
            "task_ids": [id]
          }),
          success: (response, xhr) => {
            if(response.status === true) {
              let t = response.data[id];
              // wait untill the file is reported
              if(t.status === pollUntillStatus) {
                resolve(true, t);
              } else {
                resolve(false, t);
              }
            } else {
              throw "ajax error";
              return;
            }
          },
          error: err => {
            throw err;
          }
        });

      } catch(err) {
        return reject(err);
      }

    });

    if(poll === true) {
      return new Promise((resolve, reject) => {
        let iv = setInterval(() => {
          readyCall().then(result => {
            if(result === true) {
              iv = clearInterval(iv);
              return resolve(result);
            }
          }, err => reject(err));
        }, 1000);
      }).catch(e => console.log(e));
    } else {
      // return the promise
      return readyCall();
    }

  }

}

export default GuacamoleWrapper;
