import Hookable from './Hookable';

function parseFragment(fragment) {
  if(!fragment.length) return false;
  let result = $.parseHTML(fragment.html());
  $(result).attr('id', $(fragment).attr('id'));
  return $(result);
}

class DialogInteractionScheme extends Hookable {
  constructor(dialog, interactions = {}) {

    super();

    this.dialog = dialog;
    this.interactions = interactions;

    let form = this.dialog.base.find('form');

    // respond with an interaction according to the button clicked
    // button[value]
    this.dialog.base.find('button').on('click', e => {
      let answer = $(e.currentTarget).val();
      if(this.interactions[answer]) {
        form.submit(() => this.interactions[answer](this.dialog));
      }
    });

    // prevent the form from submitting when a button has been clicked
    form.bind('submit', e => {
      e.preventDefault();
    });

  }
}

export default class RDPDialog extends Hookable {
  constructor(client, conf = {}) {
    super();
    this.client = client;
    this.base = conf.el;
    this.interaction = null;
    this.dialogs = conf.dialogs || {};
  }

  render(d) {
    let dialog = this.dialogs[d];
    if(dialog) {
      let ctx = parseFragment(dialog.template);
      this.base.find('.rdp-dialog__body').append(ctx);
      this.interactions = new DialogInteractionScheme(this, dialog.interactions);
      this.open();
    }
  }

  open() {
    this.base.prop('open', true);
  }

  close() {
    this.base.prop('open', false);
    this.base.find('.rdp-dialog__body').empty();
  }

}
