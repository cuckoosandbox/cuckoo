import Hookable from './Hookable';
import GuacamoleWrapper from './GuacWrap';
import RDPToolbar from './RDPToolbar';
import { RDPSnapshotService, RDPSnapshotSelector } from './RDPSnapshotService';
import RDPDialog, { RDPRender } from './RDPDialog';

// RDP Client wrapper for collecting all sub classes that belong to this interface
// - can be treated like a controller. Any processes are catched up on here.
class RDPClient extends Hookable {

  constructor(el) {
    super();

    this.$ = el || null;
    this.id = el.data('taskId');

    // alias internal
    let self = this;
    let taskId = this.id;

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
        // reboot: {
        //   template: $('template#rdp-dialog-reboot'),
        //   interactions: {
        //     cancel: dialog => {
        //       dialog.close();
        //     },
        //     proceed: dialog => {
        //       dialog.close();
        //     }
        //   }
        // },
        // close: {
        //   template: $('template#rdp-dialog-close'),
        //   interactions: {
        //     cancel: dialog => {
        //       dialog.close();
        //     },
        //     proceed: dialog => {
        //       dialog.close();
        //     }
        //   }
        // },
        snapshots: {
          template: $("template#rdp-dialog-snapshots"),
          model: {
            total: () => this.snapshots.total()
          },
          interactions: {
            cancel: dialog => {
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
              console.log(data);
              dialog.close();
            });

            dialog.selector.on('selected', updateSelected);
            dialog.selector.on('deselected', updateSelected);

          }
        },
        completed: {
          template: $("template#rdp-dialog-completed"),
          interactions: {
            close: dialog => {
              // the module was rendered in a new tab, closing this page
              // should take us back to the postsubmit page if still opened.
              window.close();
            },
            report: dialog => {
              window.location = `/analysis/${taskId}/summary/`;
            }
          }
        }
      }
    });

    // several other 'specific' views, controlled by an 'RDPRender' class.
    // this class resembles a simple method for spawning different custom views
    // into the viewport.
    this.errorDialog = new RDPRender(this, $("template#rdp-error"));
    this.connectingDialog = new RDPRender(this, $("template#rdp-connecting"));

    // show the connection dialog
    this.connectingDialog.render();

    // bind snapshot interactions
    this.snapshots.on('create', snapshot => {
      this.toolbar.buttons.snapshot.update();
    });

    this.snapshots.bar.on('removed', () => {
      this.toolbar.buttons.snapshot.update(true);
    });

    // error handler for service wrapper
    this.service.on('error', () => {
      // still need to do something proper here.
    });

    // initialize service wrapper
    this.service.connect();

    // start polling for status updates to cling onto
    this.service.checkReady(this.id, true).then(isReady => {
      if(isReady === true) {
        // IF SNAPSHOTS, SHOW SNAPSHOT DIALOG, THOUGH
        if(this.snapshots.total() > 0) {
          let sd = this.dialog.render('snapshots', {
            onClose: () => self.dialog.render('completed')
          });
        } else {
          this.dialog.render('completed');
        }
      }
    }).catch(e => console.log(e));

  }
}

// initialize the classes and construct the interface
$(function() {
  if($("#rdp-client").length) {
    let rdpClient = new RDPClient($("#rdp-client"));
  }
});
