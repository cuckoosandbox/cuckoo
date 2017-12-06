import Hookable from './Hookable';
import GuacamoleWrapper from './GuacWrap';
import RDPToolbar from './RDPToolbar';
import { RDPSnapshotService, RDPSnapshotSelector } from './RDPSnapshotService';
import RDPDialog from './RDPDialog';

// RDP Client wrapper for collecting all sub classes that belong to this interface
// - can be treated like a controller. Any processes are catched up on here.
class RDPClient extends Hookable {
  constructor(el) {
    super();
    this.$ = el || null;

    // connect guac service wrapper
    this.service = new GuacamoleWrapper({
      display: el.find('#guacamole-display'),
      client: this
    });

    this.snapshots = new RDPSnapshotService(this);
    this.toolbar = new RDPToolbar(this);

    // defines the UI dialogs
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
        },
        snapshots: {
          template: $("template#rdp-dialog-snapshots"),
          model: {
            total: () => this.snapshots.total()
          },
          interactions: {
            cancel: dialog => {
              console.log('Will not include selected snapshots.');
              dialog.close();
            },
            proceed: dialog => {
              // just trigger the form to submit, the event is catched in the render hook
              dialog.selector.el.submit();
            }
          },
          render: (dialog, interaction) => {

            dialog.selector = new RDPSnapshotSelector(dialog.base.find('form#snapshot-selection-form'), this.snapshots);

            let updateSelected = () => dialog.base.find('span[data-model="selected"]').text(dialog.selector.selected.length);

            dialog.selector.on('submit', data => {
              console.log('The selection is ... insert here, whatever.');
              dialog.close();
            });

            dialog.selector.on('selected', updateSelected);
            dialog.selector.on('deselected', updateSelected);

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

    // initialize the guacamole

    this.service.on('error', error => console.log(error));
    this.service.connect();

  }
}

// initialize the classes and construct the interface
$(function() {
  if($("#rdp-client").length) {
    let rdpClient = new RDPClient($("#rdp-client"));
  }
});
