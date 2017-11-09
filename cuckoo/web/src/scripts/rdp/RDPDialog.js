function parseFragment(fragment) {
  if(!fragment.length) return false;
  let result = $.parseHTML(fragment.html());
  $(result).attr('id', $(fragment).attr('id'));
  return $(result);
}

function resolveModel(model, thisArg = false) {
  let resolved = {};
  for(let m in model) {
    if(model[m] instanceof Function) {
      resolved[m] = model[m].call(thisArg || window);
    } else {
      resolved[m] = model[m];
    }
  }
  return resolved;
}

class DialogInteractionScheme {

  constructor(dialogs, dialog = {}) {

    this.parent = dialogs;
    this.dialog = dialog;
    this.interactions = dialog.interactions || {};
    this.model = resolveModel(dialog.model || {});

    let form = this.parent.base.find('form');

    // respond with an interaction according to the button clicked
    // button[value]
    this.parent.base.find('button').on('click', e => {
      let answer = $(e.currentTarget).val();
      if(this.interactions[answer]) {
        form.submit(() => this.interactions[answer](this.parent));
      }
    });

    // prevent the form from submitting when a button has been clicked
    form.bind('submit', e => {
      e.preventDefault();
    });

  }

}

export default class RDPDialog {
  constructor(client, conf = {}) {
    this.client = client;
    this.base = conf.el;
    this.interaction = null;
    this.activeModel = null;
    this.open = this.base.prop('open');
    this.dialogs = conf.dialogs || {};
  }

  render(d) {

    // don't render if a dialog is already open
    if(this.open) return;

    let dialog = this.dialogs[d];
    if(dialog) {
      let ctx = parseFragment(dialog.template);
      this.base.find('.rdp-dialog__body').append(ctx);
      this.interaction = new DialogInteractionScheme(this, dialog);
      this._injectModel(this.interaction.model);
      this.open();
    }
  }

  // opens the dialog
  open() {
    this.client.$.addClass('dialog-active');
    this.base.prop('open', true);
  }

  // closes the current dialog
  close() {
    this.client.$.removeClass('dialog-active');
    this.base.prop('open', false);
    this.base.find('.rdp-dialog__body').empty();
    this.activeModel = null;
    this.interaction = null;
  }

  // injects the model (if it has a model) into the dialog.
  _injectModel(model) {
    if(model) this.activeModel = model;
    if(this.activeModel) {
      for(let m in this.activeModel) {
        this.base.find(`*[data-model='${m}']`).text(model[m]);
      }
    }
  }

  update() {
    this._injectModel();
  }

}
