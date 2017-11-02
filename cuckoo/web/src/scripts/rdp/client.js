import Hookable from './Hookable';
import RDPToolbar from './RDPToolbar';
import RDPSnapshotService from './RDPSnapshotService';

// RDP Client wrapper for collecting all sub classes that belong to this interface
// - can be treated like a controller. Any processes are catched up on here.
class RDPClient extends Hookable {
  constructor(el) {
    super();
    this.$ = el || null;
    this.snapshots = new RDPSnapshotService(this);
    this.toolbar = new RDPToolbar(this);

    // bind snapshot interactions
    this.snapshots.on('create', snapshot => {
      this.toolbar.buttons.snapshot.update();
    });

  }
}

// initialize the classes and construct the interface
$(function() {
  if($("#rdp-client").length) {
    let rdpClient = new RDPClient($("#rdp-client"));
    console.log(rdpClient);
  }
});
