(function e(t,n,r){function s(o,u){if(!n[o]){if(!t[o]){var a=typeof require=="function"&&require;if(!u&&a)return a(o,!0);if(i)return i(o,!0);var f=new Error("Cannot find module '"+o+"'");throw f.code="MODULE_NOT_FOUND",f}var l=n[o]={exports:{}};t[o][0].call(l.exports,function(e){var n=t[o][1][e];return s(n?n:e)},l,l.exports,e,t,n,r)}return n[o].exports}var i=typeof require=="function"&&require;for(var o=0;o<r.length;o++)s(r[o]);return s})({1:[function(require,module,exports){
'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

/*
  Note: handy class to extend when you want a dead simple hook cycle system for anything you'll want to make
  triggerable.

  usage:

  const Hookable = require('./path/to/Hookable...');

  class SomeClass extends Hookable {

    constructor() {
      super();

      // define the hooks as an object with empty arrays
      this.hooks = {
        'trigger': []
      }

    }

    // dispatching hook cycles within the class
    awesomeMethod() {
      this.dispatchHook('trigger', {
        foo: 'bar',
        hello: 'world'
      });
    }

  }

  // subscribe to hooks:
  let hookie = new SomeClass();

  hookie.on('trigger', data => {
    console.log(data.foo);
  }).on('trigger', data => {
    console.log(data.hello);
  });

  // now call the method that will dispatch the trigger event:
  hookie.awesomeMethod(); // => 'bar', 'world'

 */

// empty function placeholder
var noop = function noop() {
  return true;
};

// hookable class wrapper

var Hookable = function () {
  function Hookable() {
    _classCallCheck(this, Hookable);

    this.hooks = {};
  }

  // subscribes a hook


  _createClass(Hookable, [{
    key: 'on',
    value: function on(evt) {
      var cb = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : noop;

      // create hook entry
      if (!this.hooks[evt]) this.hooks[evt] = [];
      this.hooks[evt].push(cb);
      return this;
    }

    // runs a hook cycle

  }, {
    key: 'dispatchHook',
    value: function dispatchHook() {
      var _this = this;

      var evt = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : '';
      var data = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : {};

      if (this.hooks[evt]) {
        this.hooks[evt].forEach(function (hook) {
          if (hook instanceof Function) {
            hook.call(_this, data);
          }
        });
      }
      return this;
    }
  }]);

  return Hookable;
}();

exports.default = Hookable;

},{}],2:[function(require,module,exports){
'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

var _Hookable = require('./Hookable');

var _Hookable2 = _interopRequireDefault(_Hookable);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

function parseFragment(fragment) {
  if (!fragment.length) return false;
  var result = $.parseHTML(fragment.html());
  return $(result);
}

function resolveModel(model) {
  var thisArg = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : false;

  var resolved = {};
  for (var m in model) {
    if (model[m] instanceof Function) {
      resolved[m] = model[m].call(thisArg || window);
    } else {
      resolved[m] = model[m];
    }
  }
  return resolved;
}

var DialogInteractionScheme = function DialogInteractionScheme(dialogs) {
  var _this = this;

  var dialog = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : {};

  _classCallCheck(this, DialogInteractionScheme);

  this.parent = dialogs;
  this.dialog = dialog;
  this.interactions = dialog.interactions || {};
  this.model = resolveModel(dialog.model || {});

  var form = this.parent.base.find('form.rdp-dialog__options');

  // respond with an interaction according to the button clicked
  // button[value]
  this.parent.base.find('button').on('click', function (e) {
    var answer = $(e.currentTarget).val();
    if (_this.interactions[answer]) {
      form.submit(function () {
        return _this.interactions[answer](_this.parent);
      });
    }
  });

  // prevent the form from submitting when a button has been clicked
  form.bind('submit', function (e) {
    e.preventDefault();
  });
};

var RDPDialog = function () {
  function RDPDialog(client) {
    var conf = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : {};

    _classCallCheck(this, RDPDialog);

    this.client = client;
    this.base = conf.el;
    this.interaction = null;
    this.activeModel = null;
    this.dialogs = conf.dialogs || {};
    this.isOpen = this.base.prop('open');

    this.selector = null;
  }

  _createClass(RDPDialog, [{
    key: 'render',
    value: function render(d) {

      // don't render if a dialog is already open
      if (this.isOpen) return;

      var dialog = this.dialogs[d];
      if (dialog) {
        var ctx = parseFragment(dialog.template);
        this.base.find('.rdp-dialog__body').append(ctx);
        this.interaction = new DialogInteractionScheme(this, dialog);
        this._injectModel(this.interaction.model);
        this.open();

        // runs a callback after render for anything related.
        if (dialog.render) dialog.render(this, this.interaction);
      }
    }

    // opens the dialog

  }, {
    key: 'open',
    value: function open() {
      if (!this.isOpen) {
        this.client.$.addClass('dialog-active');
        this.base.prop('open', true);
        this.isOpen = true;

        // lock interface components whilst the dialog is open.
        this.client.toolbar.disable();
        this.client.snapshots.lock(true);
      }
    }

    // closes the current dialog

  }, {
    key: 'close',
    value: function close() {
      this.client.$.removeClass('dialog-active');
      this.base.prop('open', false);
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

  }, {
    key: '_injectModel',
    value: function _injectModel(model) {
      if (model) this.activeModel = model;
      if (this.activeModel) {
        for (var m in this.activeModel) {
          this.base.find('*[data-model=\'' + m + '\']').text(model[m]);
        }
      }
    }
  }, {
    key: 'update',
    value: function update() {
      this._injectModel();
    }
  }]);

  return RDPDialog;
}();

exports.default = RDPDialog;

},{"./Hookable":1}],3:[function(require,module,exports){
'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.RDPSnapshotSelector = exports.RDPSnapshotService = undefined;

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

var _Hookable4 = require('./Hookable');

var _Hookable5 = _interopRequireDefault(_Hookable4);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

function _possibleConstructorReturn(self, call) { if (!self) { throw new ReferenceError("this hasn't been initialised - super() hasn't been called"); } return call && (typeof call === "object" || typeof call === "function") ? call : self; }

function _inherits(subClass, superClass) { if (typeof superClass !== "function" && superClass !== null) { throw new TypeError("Super expression must either be null or a function, not " + typeof superClass); } subClass.prototype = Object.create(superClass && superClass.prototype, { constructor: { value: subClass, enumerable: false, writable: true, configurable: true } }); if (superClass) Object.setPrototypeOf ? Object.setPrototypeOf(subClass, superClass) : subClass.__proto__ = superClass; }

var SnapshotBar = function (_Hookable) {
  _inherits(SnapshotBar, _Hookable);

  function SnapshotBar(el, service) {
    _classCallCheck(this, SnapshotBar);

    var _this = _possibleConstructorReturn(this, (SnapshotBar.__proto__ || Object.getPrototypeOf(SnapshotBar)).call(this));

    _this.$ = el;
    _this.service = service;
    _this.hooks = {
      'added': [],
      'removed': []
    };

    return _this;
  }

  // adds an item to the bar


  _createClass(SnapshotBar, [{
    key: 'add',
    value: function add(s) {
      var _this2 = this;

      var template = $('\n      <li data-snapshot-id="' + s.id + '">\n        <figure><img src="/static/graphic/screenshot-sample.png" alt="snapshot" /></figure>\n        <div class="rdp-snapshots--controls">\n          <a href="snapshot:remove"><i class="fa fa-remove"></i></a>\n        </div>\n      </li>\n    ');

      // append this to the list
      this.$.prepend(template);
      this.dispatchHook('added', template);

      template.find('a[href="snapshot:remove"]').bind('click', function (e) {
        e.preventDefault();

        if (_this2.service.locked) return;

        _this2.service.remove(template.data('snapshotId'));
        template.remove();
        _this2.dispatchHook('removed');
      });
    }
  }]);

  return SnapshotBar;
}(_Hookable5.default);

var Snapshot = function Snapshot(id) {
  _classCallCheck(this, Snapshot);

  this.id = id;
};

var RDPSnapshotService = function (_Hookable2) {
  _inherits(RDPSnapshotService, _Hookable2);

  function RDPSnapshotService(client) {
    _classCallCheck(this, RDPSnapshotService);

    var _this3 = _possibleConstructorReturn(this, (RDPSnapshotService.__proto__ || Object.getPrototypeOf(RDPSnapshotService)).call(this));

    _this3.client = client;
    _this3.snapshots = [];
    _this3.bar = new SnapshotBar(_this3.client.$.find('#rdp-snapshot-collection'), _this3);
    _this3.count = 0;
    _this3.locked = false;

    _this3.hooks = {
      create: [],
      remove: []
    };

    return _this3;
  }

  _createClass(RDPSnapshotService, [{
    key: 'create',
    value: function create() {

      if (this.locked) return;

      var s = new Snapshot(this.count);
      this.snapshots.push(s);
      this.count = this.count + 1;
      this.bar.add(s);
      this.dispatchHook('create', s);
    }
  }, {
    key: 'remove',
    value: function remove(id) {

      var pos = false;

      this.snapshots.forEach(function (snapshot, index) {
        if (snapshot.id == id) pos = index;
      });

      if (pos !== false) {
        this.snapshots.splice(pos, 1);
      }

      this.dispatchHook('remove', {});
    }
  }, {
    key: 'total',
    value: function total() {
      return this.snapshots.length;
    }
  }, {
    key: 'lock',
    value: function lock() {
      var isLocked = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : undefined;

      if (isLocked === undefined) {
        // toggle if no property had been given
        this.locked = !!this.locked;
      } else {
        this.locked = isLocked;
      }
    }
  }]);

  return RDPSnapshotService;
}(_Hookable5.default);

// a class for handling the selection, for now somewhat specific maybe
// but this will work for now.


var RDPSnapshotSelector = function (_Hookable3) {
  _inherits(RDPSnapshotSelector, _Hookable3);

  function RDPSnapshotSelector(el, service) {
    _classCallCheck(this, RDPSnapshotSelector);

    var _this4 = _possibleConstructorReturn(this, (RDPSnapshotSelector.__proto__ || Object.getPrototypeOf(RDPSnapshotSelector)).call(this));

    _this4.el = el; // should be a form
    _this4.snapshots = [];
    _this4.selected = [];
    _this4.service = service || null;

    _this4.hooks = {
      submit: [],
      selected: [],
      deselected: []
    };

    _this4.populate(function () {

      _this4.el.on('submit', function (e) {
        e.preventDefault();
        _this4.dispatchHook('submit', _this4.selected);
      });

      _this4.el.find('input[type="checkbox"]').bind('change', function (e) {
        var t = $(e.currentTarget);
        if (t.is(':checked')) {
          _this4.dispatchHook('selected');
        } else {
          _this4.dispatchHook('deselected');
        }
      });

      _this4.on('selected', function () {
        return _this4.selected.push({});
      });
      _this4.on('deselected', function () {
        return _this4.selected.pop();
      });
    });

    return _this4;
  }

  // populates the selection list


  _createClass(RDPSnapshotSelector, [{
    key: 'populate',
    value: function populate() {
      var done = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : function () {};


      if (!this.service) return done();

      for (var s in this.service.snapshots) {

        var snapshot = this.service.snapshots[s];

        var template = $('\n        <li>\n          <label for="snapshot-' + snapshot.id + '">\n            <input type="checkbox" name="snapshot-selection[]" value="1" id="snapshot-' + snapshot.id + '" />\n            <span class="snapshot-selection-image">\n              <img src="/static/graphic/screenshot-sample.png" alt="snapshot-' + snapshot.id + '" />\n            </span>\n          </label>\n        </li>\n      ');

        this.el.find('ul').append(template);
      }

      return done();
    }
  }]);

  return RDPSnapshotSelector;
}(_Hookable5.default);

exports.RDPSnapshotService = RDPSnapshotService;
exports.RDPSnapshotSelector = RDPSnapshotSelector;

},{"./Hookable":1}],4:[function(require,module,exports){
'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

var _Hookable2 = require('./Hookable');

var _Hookable3 = _interopRequireDefault(_Hookable2);

var _RDPToolbarButton = require('./RDPToolbarButton');

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

function _possibleConstructorReturn(self, call) { if (!self) { throw new ReferenceError("this hasn't been initialised - super() hasn't been called"); } return call && (typeof call === "object" || typeof call === "function") ? call : self; }

function _inherits(subClass, superClass) { if (typeof superClass !== "function" && superClass !== null) { throw new TypeError("Super expression must either be null or a function, not " + typeof superClass); } subClass.prototype = Object.create(superClass && superClass.prototype, { constructor: { value: subClass, enumerable: false, writable: true, configurable: true } }); if (superClass) Object.setPrototypeOf ? Object.setPrototypeOf(subClass, superClass) : subClass.__proto__ = superClass; }

function cmdKeyPressed(e) {
  return e.ctrlKey || e.metaKey || e.shiftKey || e.altKey;
}

// RDPClient.RDPToolbar

var RDPToolbar = function (_Hookable) {
  _inherits(RDPToolbar, _Hookable);

  function RDPToolbar(client) {
    _classCallCheck(this, RDPToolbar);

    var _this = _possibleConstructorReturn(this, (RDPToolbar.__proto__ || Object.getPrototypeOf(RDPToolbar)).call(this));

    _this.client = client;

    _this.buttons = {
      fullscreen: new _RDPToolbarButton.RDPToolbarButton(client.$.find('button[name="fullscreen"]'), { client: client }),
      snapshot: new _RDPToolbarButton.RDPSnapshotButton(client.$.find('button[name="screenshot"]'), { client: client }),
      control: new _RDPToolbarButton.RDPToolbarButton(client.$.find('button[name="control"]'), { client: client, holdToggle: true }),
      reboot: new _RDPToolbarButton.RDPToolbarButton(client.$.find('button[name="reboot"]'), { client: client }),
      close: new _RDPToolbarButton.RDPToolbarButton(client.$.find('button[name="close"]'), { client: client })
    };

    _this.buttons.fullscreen.on('click', function () {
      return console.log('fullscreen');
    });
    _this.buttons.snapshot.on('click', function () {
      return _this.client.snapshots.create();
    });
    _this.buttons.control.on('toggle', function (toggled) {
      return console.log('control is toggled to ' + toggled);
    });

    _this.buttons.reboot.on('click', function () {
      _this.client.dialog.render('reboot');
    });

    // if we have snapshots, show the snapshots dialog, elsely show the default
    // close dialog.
    _this.buttons.close.on('click', function () {
      if (_this.client.snapshots.total() > 0) {
        _this.client.dialog.render('snapshots');
      } else {
        _this.client.dialog.render('close');
      }
    });

    $('body').on('keydown', function (e) {

      // prevent triggering when in ctrl/alt/shift key modes, usually reserved for browser actions or
      // OS UX, semantically that should never break so we should prevent it, as well.
      if (cmdKeyPressed(e)) return;

      switch (e.keyCode) {
        case 83:
          _this.buttons.snapshot.dispatchHook('click');
          _this.buttons.snapshot.blink();
          break;
        case 70:
          _this.buttons.fullscreen.dispatchHook('click');
          _this.buttons.fullscreen.blink();
          break;
        case 67:
          _this.buttons.control.$.trigger('mousedown');
          break;
        case 82:
          _this.buttons.reboot.dispatchHook('click');
          _this.buttons.reboot.blink();
          break;
        case 81:
          _this.buttons.close.dispatchHook('click');
          _this.buttons.close.blink();
          break;
      }
    });

    return _this;
  }

  // lock the entire toolbar with one method calling
  // button.disable(true).


  _createClass(RDPToolbar, [{
    key: 'disable',
    value: function disable() {
      for (var button in this.buttons) {
        this.buttons[button].disable(true);
      }
    }

    // unlock the entire toolbar with one method calling
    // button.disable(false).

  }, {
    key: 'enable',
    value: function enable() {
      for (var button in this.buttons) {
        this.buttons[button].disable(false);
      }
    }
  }]);

  return RDPToolbar;
}(_Hookable3.default);

exports.default = RDPToolbar;

},{"./Hookable":1,"./RDPToolbarButton":5}],5:[function(require,module,exports){
'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.RDPSnapshotButton = exports.RDPToolbarButton = undefined;

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

var _Hookable2 = require('./Hookable');

var _Hookable3 = _interopRequireDefault(_Hookable2);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

function _possibleConstructorReturn(self, call) { if (!self) { throw new ReferenceError("this hasn't been initialised - super() hasn't been called"); } return call && (typeof call === "object" || typeof call === "function") ? call : self; }

function _inherits(subClass, superClass) { if (typeof superClass !== "function" && superClass !== null) { throw new TypeError("Super expression must either be null or a function, not " + typeof superClass); } subClass.prototype = Object.create(superClass && superClass.prototype, { constructor: { value: subClass, enumerable: false, writable: true, configurable: true } }); if (superClass) Object.setPrototypeOf ? Object.setPrototypeOf(subClass, superClass) : subClass.__proto__ = superClass; }

// RDPClient.RDPToolbarButton
var RDPToolbarButton = function (_Hookable) {
  _inherits(RDPToolbarButton, _Hookable);

  function RDPToolbarButton(element) {
    var conf = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : {};

    _classCallCheck(this, RDPToolbarButton);

    var _this = _possibleConstructorReturn(this, (RDPToolbarButton.__proto__ || Object.getPrototypeOf(RDPToolbarButton)).call(this));

    _this.$ = element;
    _this.client = conf.client;
    _this.holdToggle = conf.holdToggle || false;
    _this.toggled = _this.$.hasClass('active');
    _this.isDisabled = !!_this.$.attr('disabled');

    _this.hooks = {
      click: [],
      toggle: [],
      disabled: []
    };

    // apply basic interaction listeners
    _this.$.bind('mousedown', function (e) {
      _this.dispatchHook('click', {});

      // handle toggle-able buttons correctly
      if (_this.holdToggle) {
        _this.$.toggleClass('active');
        _this.toggled = _this.$.hasClass('active');
        _this.dispatchHook('toggle', _this.toggled);
      }
    });

    return _this;
  }

  // quick method for disabling buttons


  _createClass(RDPToolbarButton, [{
    key: 'disable',
    value: function disable(_disable) {
      if (_disable === undefined) {
        this.$.prop('disabled', !!this.disabled);
      } else {
        this.$.prop('disabled', _disable);
      }

      this.disabled = this.$.prop('disabled');
      this.dispatchHook('disabled');
    }

    // a 'blink' effect to emulate a press visually

  }, {
    key: 'blink',
    value: function blink() {
      var _this2 = this;

      this.$.addClass('active');
      setTimeout(function () {
        return _this2.$.removeClass('active');
      }, 150);
    }
  }]);

  return RDPToolbarButton;
}(_Hookable3.default);

// variety: snapshot button, contains some controls for the graphical
// enhancemants that come with it.


var RDPSnapshotButton = function (_RDPToolbarButton) {
  _inherits(RDPSnapshotButton, _RDPToolbarButton);

  function RDPSnapshotButton(element) {
    var conf = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : {};

    _classCallCheck(this, RDPSnapshotButton);

    var _this3 = _possibleConstructorReturn(this, (RDPSnapshotButton.__proto__ || Object.getPrototypeOf(RDPSnapshotButton)).call(this, element, conf));

    _this3.$ = _this3.$.parent();
    return _this3;
  }

  _createClass(RDPSnapshotButton, [{
    key: 'update',
    value: function update() {
      var _this4 = this;

      var isRemoved = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : false;


      var total = this.client.snapshots.total();
      this.$.find('.button-badge').text(total);

      if (!isRemoved) {

        if (total <= 3) {
          this.$.find('.ss-v-e-' + total).addClass('in');
        }

        this.$.find('button').addClass('shutter-in');
        setTimeout(function () {
          return _this4.$.find('button').removeClass('shutter-in');
        }, 1500);
      } else {

        // this is something that could be done better, but works for now.
        if (total == 2) this.$.find('.ss-v-e-3').removeClass('in');
        if (total == 1) this.$.find('.ss-v-e-2').removeClass('in');
        if (total == 0) {
          this.$.find('.ss-v-e-1').removeClass('in');
          this.$.find('.button-badge').text('');
        }
      }
    }

    // litte changes in the disable method for this button, as the $ is not a button.

  }, {
    key: 'disable',
    value: function disable(_disable2) {
      if (_disable2 === undefined) {
        this.$.find('button').prop('disabled', !!this.disabled);
      } else {
        this.$.find('button').prop('disabled', _disable2);
      }

      this.isDisabled = this.$.find('button').prop('disabled');
      this.dispatchHook('disabled', this.isDisabled);
    }
  }]);

  return RDPSnapshotButton;
}(RDPToolbarButton);

exports.RDPToolbarButton = RDPToolbarButton;
exports.RDPSnapshotButton = RDPSnapshotButton;

},{"./Hookable":1}],6:[function(require,module,exports){
'use strict';

var _Hookable2 = require('./Hookable');

var _Hookable3 = _interopRequireDefault(_Hookable2);

var _RDPToolbar = require('./RDPToolbar');

var _RDPToolbar2 = _interopRequireDefault(_RDPToolbar);

var _RDPSnapshotService = require('./RDPSnapshotService');

var _RDPDialog = require('./RDPDialog');

var _RDPDialog2 = _interopRequireDefault(_RDPDialog);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

function _possibleConstructorReturn(self, call) { if (!self) { throw new ReferenceError("this hasn't been initialised - super() hasn't been called"); } return call && (typeof call === "object" || typeof call === "function") ? call : self; }

function _inherits(subClass, superClass) { if (typeof superClass !== "function" && superClass !== null) { throw new TypeError("Super expression must either be null or a function, not " + typeof superClass); } subClass.prototype = Object.create(superClass && superClass.prototype, { constructor: { value: subClass, enumerable: false, writable: true, configurable: true } }); if (superClass) Object.setPrototypeOf ? Object.setPrototypeOf(subClass, superClass) : subClass.__proto__ = superClass; }

// RDP Client wrapper for collecting all sub classes that belong to this interface
// - can be treated like a controller. Any processes are catched up on here.
var RDPClient = function (_Hookable) {
  _inherits(RDPClient, _Hookable);

  function RDPClient(el) {
    _classCallCheck(this, RDPClient);

    var _this = _possibleConstructorReturn(this, (RDPClient.__proto__ || Object.getPrototypeOf(RDPClient)).call(this));

    _this.$ = el || null;
    _this.snapshots = new _RDPSnapshotService.RDPSnapshotService(_this);
    _this.toolbar = new _RDPToolbar2.default(_this);

    // defines the UI dialogs
    _this.dialog = new _RDPDialog2.default(_this, {
      el: el.find('#rdp-dialog'),
      dialogs: {
        reboot: {
          template: $('template#rdp-dialog-reboot'),
          interactions: {
            cancel: function cancel(dialog) {
              console.log('Will not reboot.');
              dialog.close();
            },
            proceed: function proceed(dialog) {
              console.log('Will reboot.');
              dialog.close();
            }
          }
        },
        close: {
          template: $('template#rdp-dialog-close'),
          interactions: {
            cancel: function cancel(dialog) {
              console.log('Will not close');
              dialog.close();
            },
            proceed: function proceed(dialog) {
              console.log('Will close');
              dialog.close();
            }
          }
        },
        snapshots: {
          template: $("template#rdp-dialog-snapshots"),
          model: {
            total: function total() {
              return _this.snapshots.total();
            }
          },
          interactions: {
            cancel: function cancel(dialog) {
              console.log('Will not include selected snapshots.');
              dialog.close();
            },
            proceed: function proceed(dialog) {
              // just trigger the form to submit, the event is catched in the render hook
              dialog.selector.el.submit();
            }
          },
          render: function render(dialog, interaction) {

            dialog.selector = new _RDPSnapshotService.RDPSnapshotSelector(dialog.base.find('form#snapshot-selection-form'), _this.snapshots);

            var updateSelected = function updateSelected() {
              return dialog.base.find('span[data-model="selected"]').text(dialog.selector.selected.length);
            };

            dialog.selector.on('submit', function (data) {
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
    _this.snapshots.on('create', function (snapshot) {
      _this.toolbar.buttons.snapshot.update();
    });

    _this.snapshots.bar.on('removed', function () {
      _this.toolbar.buttons.snapshot.update(true);
    });

    return _this;
  }

  return RDPClient;
}(_Hookable3.default);

// initialize the classes and construct the interface


$(function () {
  if ($("#rdp-client").length) {
    var rdpClient = new RDPClient($("#rdp-client"));
  }
});

},{"./Hookable":1,"./RDPDialog":2,"./RDPSnapshotService":3,"./RDPToolbar":4}]},{},[6])


//# sourceMappingURL=rdp.js.map
