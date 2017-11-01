import Hookable from './Hookable';
import { RDPToolbarButton, RDPSnapshotButton } from './RDPToolbarButton';

// RDPClient.RDPToolbar
export default class RDPToolbar extends Hookable {
  constructor(client) {

    super();

    this.client = client;

    this.buttons = {
      fullscreen: new RDPToolbarButton(client.$.find('button[name="fullscreen"]'), { client }),
      snapshot: new RDPSnapshotButton(client.$.find('button[name="snapshot"]'), { client }),
      control: new RDPToolbarButton(client.$.find('button[name="control"]'), { client, holdToggle: true }),
      reboot: new RDPToolbarButton(client.$.find('button[name="reboot"]'), { client }),
      close: new RDPToolbarButton(client.$.find('button[name="close"]'), { client })
    }

    this.buttons.fullscreen.on('click', () => console.log('fullscreen'));
    this.buttons.snapshot.on('click', () => console.log('make a snapshot'));
    this.buttons.control.on('toggle', toggled => console.log(`control is toggled to ${toggled}`));
    this.buttons.reboot.on('click', () => console.log('reboot the system'));
    this.buttons.close.on('click', () => console.log('closing this session.'));

  }
}
