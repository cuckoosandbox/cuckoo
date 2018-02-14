import Hookable from './Hookable';

function parseFragment(fragment, parsejQuery = true) {
  if(!fragment.length) return false;
  let result = fragment.html();
  return parsejQuery ? $(result) : result;
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

/*
  The error state is not really a dialog, but this class will take care of rendering
  an error inside the viewport as a substitute class.
 */
class RDPRender {
  constructor(client, template) {
    this.client = client;
    this.template = parseFragment(template);
    this.active = false;
  }
  render() {
    if(!this.template) return;
    this.client.$.find('.rdp-app__viewport').html(this.template);
    this.active = true;
  }
  destroy() {
    this.template.remove();
  }
}

class DialogInteractionScheme {

  constructor(dialogs, dialog = {}) {

    this.parent = dialogs;
    this.dialog = dialog;
    this.interactions = dialog.interactions || {};
    this.model = resolveModel(dialog.model || {});

    let form = this.parent.base.find('form.rdp-dialog__options');

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
    this.dialogs = conf.dialogs || {};
    this.isOpen = this.base.prop('open');
    this.onClose = null;
    this.beforeRender = null;

    this.selector = null;

  }

  render(d, opts = {}) {

    // don't render if a dialog is already open
    if(this.isOpen) return;

    // attach onClose handler
    if(opts.onClose && opts.onClose instanceof Function) {
      this.onClose = opts.onClose;
    }

    // attach beforeRender handler
    if(opts.beforeRender && opts.beforeRender instanceof Function) {
      this.beforeRender = opts.beforeRender;
    }

    let dialog = this.dialogs[d];

    if(dialog) {
      let ctx = parseFragment(dialog.template);
      if(this.beforeRender) this.beforeRender();
      this.base.find('.rdp-dialog__body').append(ctx);
      this.interaction = new DialogInteractionScheme(this, dialog);
      this._injectModel(this.interaction.model);
      this.open();

      // runs a callback after render for anything related.
      if(dialog.render) dialog.render(this, this.interaction);
    }

    return dialog;

  }

  // opens the dialog
  open() {
    if(!this.isOpen) {
      this.client.$.addClass('dialog-active');
      this.base.attr('open', true);
      this.isOpen = true;

      // lock interface components whilst the dialog is open.
      this.client.toolbar.disable();
      this.client.snapshots.lock(true);
    }
  }

  // closes the current dialog
  close() {

    if(this.onClose) {
      setTimeout(() => {
        this.onClose();
        this.onClose = null;
      }, 150);
    }

    this.client.$.removeClass('dialog-active');
    this.base.attr('open', false);
    this.base.find('.rdp-dialog__body').empty();
    this.activeModel = null;
    this.interaction = null;
    this.selector = null;
    this.isOpen = false;

    // re-enable other interface components again when closing
    this.client.toolbar.enable();
    this.client.snapshots.lock(false);

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

// export other functions
export { RDPRender }
