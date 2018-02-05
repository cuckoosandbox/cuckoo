import Hookable from './Hookable';
import { RDPToolbarButton, RDPSnapshotButton } from './RDPToolbarButton';

function cmdKeyPressed(e) {
  return e.ctrlKey || e.metaKey || e.shiftKey || e.altKey;
}

// RDPClient.RDPToolbar
export default class RDPToolbar extends Hookable {
  constructor(client) {

    super();

    this.client = client;

    this.buttons = {
      fullscreen: new RDPToolbarButton(client.$.find('button[name="fullscreen"]'), { client }),
      snapshot: new RDPSnapshotButton(client.$.find('button[name="screenshot"]'), { client }),
      control: new RDPToolbarButton(client.$.find('button[name="control"]'), { client, holdToggle: true })
    }

    // toggle fullscreen mode
    this.buttons.fullscreen.on('click', () => {
      if(CuckooWeb.isFullscreen()) {
        CuckooWeb.exitFullscreen();
      } else {
        CuckooWeb.requestFullscreen(document.getElementById('rdp-client'));
      }
    });

    // make a slight change to the client style to fit into viewport after a
    // change of fullscreen-ness.
    CuckooWeb.onFullscreenChange(e => this.client.$.toggleClass('fullscreen', CuckooWeb.isFullscreen()));

    // snapshots
    this.buttons.snapshot.on('click', () => {
      let image = this.client.snapshots.capture();
      this.client.snapshots.create(image);
    });

    // toggles control modes
    this.buttons.control.on('toggle', toggled => {
      if(toggled) {
        // enable mouse and keyboard
        this.client.service.mouse(true);
        this.client.service.keyboard(true);
      } else {
        // disable mouse and keyboard
        this.client.service.mouse(false);
        this.client.service.keyboard(false);
      }
    });

    $('body').on('keydown', e => {

      // prevent triggering when in ctrl/alt/shift key modes, usually reserved for browser actions or
      // OS UX, semantically that should never break so we should prevent it, as well.
      if(cmdKeyPressed(e)) return;

      // in 'control' mode, we do not do shortcut keys to prioritize keyboard interactions to the vm
      if(this.buttons.control.toggled) return;

      switch(e.keyCode) {
        case 83:
          this.buttons.snapshot.dispatchHook('click');
          this.buttons.snapshot.blink();
        break;
        case 70:
          this.buttons.fullscreen.dispatchHook('click');
          this.buttons.fullscreen.blink();
        break;
        case 67:
          this.buttons.control.$.trigger('mousedown');
        break;
      }

    });

  }

  // lock the entire toolbar with one method calling
  // button.disable(true).
  disable() {
    for(let button in this.buttons) this.buttons[button].disable(true);
  }

  // unlock the entire toolbar with one method calling
  // button.disable(false).
  enable() {
    for(let button in this.buttons) this.buttons[button].disable(false);
  }

}
