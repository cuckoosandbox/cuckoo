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

var _Hookable3 = require('./Hookable');

var _Hookable4 = _interopRequireDefault(_Hookable3);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

function _possibleConstructorReturn(self, call) { if (!self) { throw new ReferenceError("this hasn't been initialised - super() hasn't been called"); } return call && (typeof call === "object" || typeof call === "function") ? call : self; }

function _inherits(subClass, superClass) { if (typeof superClass !== "function" && superClass !== null) { throw new TypeError("Super expression must either be null or a function, not " + typeof superClass); } subClass.prototype = Object.create(superClass && superClass.prototype, { constructor: { value: subClass, enumerable: false, writable: true, configurable: true } }); if (superClass) Object.setPrototypeOf ? Object.setPrototypeOf(subClass, superClass) : subClass.__proto__ = superClass; }

function parseFragment(fragment) {
  if (!fragment.length) return false;
  var result = $.parseHTML(fragment.html());
  $(result).attr('id', $(fragment).attr('id'));
  return $(result);
}

var DialogInteractionScheme = function (_Hookable) {
  _inherits(DialogInteractionScheme, _Hookable);

  function DialogInteractionScheme(dialog) {
    var interactions = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : {};

    _classCallCheck(this, DialogInteractionScheme);

    var _this = _possibleConstructorReturn(this, (DialogInteractionScheme.__proto__ || Object.getPrototypeOf(DialogInteractionScheme)).call(this));

    _this.dialog = dialog;
    _this.interactions = interactions;

    var form = _this.dialog.base.find('form');

    // respond with an interaction according to the button clicked
    // button[value]
    _this.dialog.base.find('button').on('click', function (e) {
      var answer = $(e.currentTarget).val();
      if (_this.interactions[answer]) {
        form.submit(function () {
          return _this.interactions[answer](_this.dialog);
        });
      }
    });

    // prevent the form from submitting when a button has been clicked
    form.bind('submit', function (e) {
      e.preventDefault();
    });

    return _this;
  }

  return DialogInteractionScheme;
}(_Hookable4.default);

var RDPDialog = function (_Hookable2) {
  _inherits(RDPDialog, _Hookable2);

  function RDPDialog(client) {
    var conf = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : {};

    _classCallCheck(this, RDPDialog);

    var _this2 = _possibleConstructorReturn(this, (RDPDialog.__proto__ || Object.getPrototypeOf(RDPDialog)).call(this));

    _this2.client = client;
    _this2.base = conf.el;
    _this2.interaction = null;
    _this2.dialogs = conf.dialogs || {};
    return _this2;
  }

  _createClass(RDPDialog, [{
    key: 'render',
    value: function render(d) {
      var dialog = this.dialogs[d];
      if (dialog) {
        var ctx = parseFragment(dialog.template);
        this.base.find('.rdp-dialog__body').append(ctx);
        this.interactions = new DialogInteractionScheme(this, dialog.interactions);
        this.open();
      }
    }
  }, {
    key: 'open',
    value: function open() {
      this.base.prop('open', true);
    }
  }, {
    key: 'close',
    value: function close() {
      this.base.prop('open', false);
      this.base.find('.rdp-dialog__body').empty();
    }
  }]);

  return RDPDialog;
}(_Hookable4.default);

exports.default = RDPDialog;

},{"./Hookable":1}],3:[function(require,module,exports){
'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

var _Hookable3 = require('./Hookable');

var _Hookable4 = _interopRequireDefault(_Hookable3);

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
        _this2.service.remove(template.data('snapshotId'));
        template.remove();
        _this2.dispatchHook('removed');
      });
    }
  }]);

  return SnapshotBar;
}(_Hookable4.default);

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

    _this3.hooks = {
      create: [],
      remove: []
    };

    return _this3;
  }

  _createClass(RDPSnapshotService, [{
    key: 'create',
    value: function create() {
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
  }]);

  return RDPSnapshotService;
}(_Hookable4.default);

exports.default = RDPSnapshotService;

},{"./Hookable":1}],4:[function(require,module,exports){
'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});

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
      snapshot: new _RDPToolbarButton.RDPSnapshotButton(client.$.find('button[name="snapshot"]'), { client: client }),
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

    _this.buttons.close.on('click', function () {
      _this.client.dialog.render('close');
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

var _RDPSnapshotService2 = _interopRequireDefault(_RDPSnapshotService);

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
    _this.snapshots = new _RDPSnapshotService2.default(_this);
    _this.toolbar = new _RDPToolbar2.default(_this);

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