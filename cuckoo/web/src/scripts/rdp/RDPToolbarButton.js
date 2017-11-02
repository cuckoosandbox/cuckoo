import Hookable from './Hookable';

// RDPClient.RDPToolbarButton
class RDPToolbarButton extends Hookable {

  constructor(element, conf = {}) {

    super();

    this.$ = element;
    this.client = conf.client;
    this.holdToggle = conf.holdToggle || false;
    this.toggled = this.$.hasClass('active');
    this.disabled = !!this.$.attr('disabled');

    this.hooks = {
      click: [],
      toggle: [],
      disabled: []
    }

    // apply basic interaction listeners
    this.$.bind('mousedown', e => {
      this.dispatchHook('click', {});

      // handle toggle-able buttons correctly
      if(this.holdToggle) {
        this.$.toggleClass('active');
        this.toggled = this.$.hasClass('active');
        this.dispatchHook('toggle', this.toggled);
      }

    });

  }

  // quick method for disabling buttons
  disable(disable) {
    if(disable === undefined) {
      this.$.prop('disabled', !!this.disabled);
    } else {
      this.$.prop('disabled', disable);
    }

    this.dispatchHook('disabled');
  }

}

// variety: snapshot button, contains some controls for the graphical
// enhancemants that come with it.
class RDPSnapshotButton extends RDPToolbarButton {

  constructor(element, conf = {}) {
    super(element, conf);
    this.$ = this.$.parent();
  }

  update() {
    let total = this.client.snapshots.total();
    this.$.find('.button-badge').text(total);

    if(total <= 3) {
      this.$.find(`.ss-v-e-${total}`).addClass('in');
    }

  }

}

export { RDPToolbarButton, RDPSnapshotButton };
