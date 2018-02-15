import Hookable from './Hookable';

// RDPClient.RDPToolbarButton
class RDPToolbarButton extends Hookable {

  constructor(element, conf = {}) {

    super();

    this.$ = element;
    this.client = conf.client;
    this.holdToggle = conf.holdToggle || false;
    this.toggled = this.$.hasClass('active');
    this.isDisabled = !!this.$.attr('disabled');

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

    this.disabled = this.$.prop('disabled');
    this.dispatchHook('disabled');
  }

  // a 'blink' effect to emulate a press visually
  blink() {
    this.$.addClass('active');
    setTimeout(() => this.$.removeClass('active'), 150);
  }

}

// variety: snapshot button, contains some controls for the graphical
// enhancemants that come with it.
class RDPSnapshotButton extends RDPToolbarButton {

  constructor(element, conf = {}) {
    super(element, conf);
    this.$ = this.$.parent();
  }

  update(isRemoved = false) {

    let total = this.client.snapshots.total();
    this.$.find('.button-badge').text(total);

    if(!isRemoved) {

      if(total <= 3) {
        this.$.find(`.ss-v-e-${total}`).addClass('in');
      }

      this.$.find('button').addClass('shutter-in');
      setTimeout(() => this.$.find('button').removeClass('shutter-in'), 1500);

    } else {

      // this is something that could be done better, but works for now.
      if(total == 2) this.$.find(`.ss-v-e-3`).removeClass('in');
      if(total == 1) this.$.find('.ss-v-e-2').removeClass('in');
      if(total == 0) {
        this.$.find('.ss-v-e-1').removeClass('in');
        this.$.find('.button-badge').text('');
      }


    }

  }

  // litte changes in the disable method for this button, as the $ is not a button.
  disable(disable) {
    if(disable === undefined) {
      this.$.find('button').prop('disabled', !!this.disabled);
    } else {
      this.$.find('button').prop('disabled', disable);
    }

    this.isDisabled = this.$.find('button').prop('disabled');
    this.dispatchHook('disabled', this.isDisabled);
  }

}

export { RDPToolbarButton, RDPSnapshotButton };
