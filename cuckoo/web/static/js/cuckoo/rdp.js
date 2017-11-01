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

var _Hookable2 = require('./Hookable');

var _Hookable3 = _interopRequireDefault(_Hookable2);

var _RDPToolbarButton = require('./RDPToolbarButton');

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

function _possibleConstructorReturn(self, call) { if (!self) { throw new ReferenceError("this hasn't been initialised - super() hasn't been called"); } return call && (typeof call === "object" || typeof call === "function") ? call : self; }

function _inherits(subClass, superClass) { if (typeof superClass !== "function" && superClass !== null) { throw new TypeError("Super expression must either be null or a function, not " + typeof superClass); } subClass.prototype = Object.create(superClass && superClass.prototype, { constructor: { value: subClass, enumerable: false, writable: true, configurable: true } }); if (superClass) Object.setPrototypeOf ? Object.setPrototypeOf(subClass, superClass) : subClass.__proto__ = superClass; }

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
      return console.log('make a snapshot');
    });
    _this.buttons.control.on('toggle', function (toggled) {
      return console.log('control is toggled to ' + toggled);
    });
    _this.buttons.reboot.on('click', function () {
      return console.log('reboot the system');
    });
    _this.buttons.close.on('click', function () {
      return console.log('closing this session.');
    });

    return _this;
  }

  return RDPToolbar;
}(_Hookable3.default);

exports.default = RDPToolbar;

},{"./Hookable":1,"./RDPToolbarButton":3}],3:[function(require,module,exports){
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
    _this.disabled = !!_this.$.attr('disabled');

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

      this.dispatchHook('disabled');
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

    return _possibleConstructorReturn(this, (RDPSnapshotButton.__proto__ || Object.getPrototypeOf(RDPSnapshotButton)).call(this, element, conf));
  }

  return RDPSnapshotButton;
}(RDPToolbarButton);

exports.RDPToolbarButton = RDPToolbarButton;
exports.RDPSnapshotButton = RDPSnapshotButton;

},{"./Hookable":1}],4:[function(require,module,exports){
'use strict';

var _Hookable2 = require('./Hookable');

var _Hookable3 = _interopRequireDefault(_Hookable2);

var _RDPToolbar = require('./RDPToolbar');

var _RDPToolbar2 = _interopRequireDefault(_RDPToolbar);

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
    _this.toolbar = new _RDPToolbar2.default(_this);
    return _this;
  }

  return RDPClient;
}(_Hookable3.default);

// initialize the classes and construct the interface


$(function () {
  if ($("#rdp-client").length) {
    var rdpClient = new RDPClient($("#rdp-client"));
    console.log(rdpClient);
  }
});

},{"./Hookable":1,"./RDPToolbar":2}]},{},[4])


//# sourceMappingURL=rdp.js.map
