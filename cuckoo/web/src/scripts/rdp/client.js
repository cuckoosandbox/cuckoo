import Hookable from './Hookable';
import RDPToolbar from './RDPToolbar';

// RDP Client wrapper for collecting all sub classes that belong to this interface
// - can be treated like a controller. Any processes are catched up on here.
class RDPClient extends Hookable {
  constructor(el) {
    super();
    this.$ = el || null;
    this.toolbar = new RDPToolbar(this);
  }
}

// initialize the classes and construct the interface
$(function() {
  if($("#rdp-client").length) {
    let rdpClient = new RDPClient($("#rdp-client"));
    console.log(rdpClient);
  }
});
