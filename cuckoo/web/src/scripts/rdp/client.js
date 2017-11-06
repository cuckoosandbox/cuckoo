import Hookable from './Hookable';
import RDPToolbar from './RDPToolbar';
import RDPSnapshotService from './RDPSnapshotService';
import RDPDialog from './RDPDialog';

// RDP Client wrapper for collecting all sub classes that belong to this interface
// - can be treated like a controller. Any processes are catched up on here.
class RDPClient extends Hookable {
  constructor(el) {
    super();
    this.$ = el || null;
    this.snapshots = new RDPSnapshotService(this);
    this.toolbar = new RDPToolbar(this);

    this.dialog = new RDPDialog(this, {
      el: el.find('#rdp-dialog'),
      dialogs: {
        reboot: {
          template: $('template#rdp-dialog-reboot'),
          interactions: {
            cancel: dialog => {
              console.log('Will not reboot.');
              dialog.close();
            },
            proceed: dialog => {
              console.log('Will reboot.');
              dialog.close();
            }
          }
        },
        close: {
          template: $('template#rdp-dialog-close'),
          interactions: {
            cancel: dialog => {
              console.log('Will not close');
              dialog.close();
            },
            proceed: dialog => {
              console.log('Will close');
              dialog.close();
            }
          }
        }
      }
    });

    // bind snapshot interactions
    this.snapshots.on('create', snapshot => {
      this.toolbar.buttons.snapshot.update();
    });

    this.snapshots.bar.on('removed', () => {
      this.toolbar.buttons.snapshot.update(true);
    });

  }
}

// initialize the classes and construct the interface
$(function() {
  if($("#rdp-client").length) {
    let rdpClient = new RDPClient($("#rdp-client"));
  }
});
