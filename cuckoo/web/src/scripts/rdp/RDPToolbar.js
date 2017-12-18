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
      control: new RDPToolbarButton(client.$.find('button[name="control"]'), { client, holdToggle: true }),
      reboot: new RDPToolbarButton(client.$.find('button[name="reboot"]'), { client }),
      close: new RDPToolbarButton(client.$.find('button[name="close"]'), { client })
    }

    // toggle fullscreen mode
    this.buttons.fullscreen.on('click', () => {
      if(CuckooWeb.isFullsceen()) {
        this.client.$.removeClass('fullscreen');
        CuckooWeb.exitFullscreen();
      } else {
        this.client.$.addClass('fullscreen');
        CuckooWeb.requestFullscreen(document.getElementById('rdp-client'));
      }
    });

    // snapshots
    this.buttons.snapshot.on('click', () => this.client.snapshots.create());

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

    this.buttons.reboot.on('click', () => {
      this.client.dialog.render('reboot');
    });

    // if we have snapshots, show the snapshots dialog, elsely show the default
    // close dialog.
    this.buttons.close.on('click', () => {
      if(this.client.snapshots.total() > 0) {
        this.client.dialog.render('snapshots');
      } else {
        this.client.dialog.render('close');
      }
    });

    $('body').on('keydown', e => {

      // prevent triggering when in ctrl/alt/shift key modes, usually reserved for browser actions or
      // OS UX, semantically that should never break so we should prevent it, as well.
      if(cmdKeyPressed(e)) return;

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
        case 82:
          this.buttons.reboot.dispatchHook('click');
          this.buttons.reboot.blink();
        break;
        case 81:
          this.buttons.close.dispatchHook('click');
          this.buttons.close.blink();
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
