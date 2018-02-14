(function e(t,n,r){function s(o,u){if(!n[o]){if(!t[o]){var a=typeof require=="function"&&require;if(!u&&a)return a(o,!0);if(i)return i(o,!0);var f=new Error("Cannot find module '"+o+"'");throw f.code="MODULE_NOT_FOUND",f}var l=n[o]={exports:{}};t[o][0].call(l.exports,function(e){var n=t[o][1][e];return s(n?n:e)},l,l.exports,e,t,n,r)}return n[o].exports}var i=typeof require=="function"&&require;for(var o=0;o<r.length;o++)s(r[o]);return s})({1:[function(require,module,exports){
'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

var _Hookable2 = require('./Hookable');

var _Hookable3 = _interopRequireDefault(_Hookable2);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

function _possibleConstructorReturn(self, call) { if (!self) { throw new ReferenceError("this hasn't been initialised - super() hasn't been called"); } return call && (typeof call === "object" || typeof call === "function") ? call : self; }

function _inherits(subClass, superClass) { if (typeof superClass !== "function" && superClass !== null) { throw new TypeError("Super expression must either be null or a function, not " + typeof superClass); } subClass.prototype = Object.create(superClass && superClass.prototype, { constructor: { value: subClass, enumerable: false, writable: true, configurable: true } }); if (superClass) Object.setPrototypeOf ? Object.setPrototypeOf(subClass, superClass) : subClass.__proto__ = superClass; }

var GuacamoleWrapper = function (_Hookable) {
  _inherits(GuacamoleWrapper, _Hookable);

  function GuacamoleWrapper(props) {
    _classCallCheck(this, GuacamoleWrapper);

    // api hooks
    var _this = _possibleConstructorReturn(this, (GuacamoleWrapper.__proto__ || Object.getPrototypeOf(GuacamoleWrapper)).call(this));

    _this.hooks = {
      connect: [],
      error: [],
      end: []
    };

    // detect Guacamole
    if (!window.Guacamole) {
      var _ret;

      console.error('No Guacamole! Did you forget to process the avocados in src/scripts/rdp/guac?');
      return _ret = false, _possibleConstructorReturn(_this, _ret);
    }

    // properties
    _this.display = props.display;
    _this.parent = props.client; // 'parent' client wrapper
    _this.client = null; // reserved for the Guacamole client (created on connect)
    _this._mouse = null;
    _this._keyboard = null;

    return _this;
  }

  /*
    GuacamoleWrapper.connect
    - connects to the RDP server
   */


  _createClass(GuacamoleWrapper, [{
    key: 'connect',
    value: function connect() {
      var _this2 = this;

      // create the client
      var tunnel = new Guacamole.HTTPTunnel("tunnel/");
      var guac = this.client = new Guacamole.Client(tunnel);;

      // create the display
      this.display.html(guac.getDisplay().getElement());

      tunnel.onerror = guac.onerror = function (error) {
        // skipping over error codes, for instance: the ending session is
        // also thrown as an error, so taking advantage of the status code to
        // delegate the correct
        switch (error.code) {
          case 523:
            break;
          default:
            _this2.dispatchHook('error', error);
        }
      };

      tunnel.onstatechange = function (state) {
        if (state == 2) {
          _this2.dispatchHook('ended');
        }
      };

      guac.connect();
      this.dispatchHook('connect', guac);
    }

    /*
      GuacamoleWrapper.mouse
      - handles mouse interaction
     */

  }, {
    key: 'mouse',
    value: function mouse() {
      var _this3 = this;

      var enable = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : true;

      if (!this.client) return;

      if (enable) {
        (function () {
          _this3._mouse = new Guacamole.Mouse(_this3.client.getDisplay().getElement());
          var sendState = function sendState(state) {
            return _this3.client.sendMouseState(state);
          };

          // apply sendState function
          _this3._mouse.onmousemove = _this3._mouse.onmouseup = _this3._mouse.onmousedown = function (state) {
            if (_this3.parent.toolbar.buttons.control.toggled) {
              sendState(state);
            }
          };
        })();
      }
    }

    /*
      GuacamoleWrapper.keyboard
      - handles keyboard interaction
     */

  }, {
    key: 'keyboard',
    value: function keyboard() {
      var _this4 = this;

      var enable = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : true;


      if (!this.client) return;

      if (enable) {
        this._keyboard = new Guacamole.Keyboard(document);
        this._keyboard.onkeydown = function (keysym) {
          if (_this4.parent.toolbar.buttons.control.toggled) {
            _this4.client.sendKeyEvent(1, keysym);
          }
        };
        this._keyboard.onkeyup = function (keysym) {
          if (_this4.parent.toolbar.buttons.control.toggled) {
            _this4.client.sendKeyEvent(0, keysym);
          }
        };
      } else {
        this._keyboard = null;
      }
    }

    /*
      GuacamoleWrapper.getCanvas
      - shortcut for returning default guac layer (active tunnel viewport)
     */

  }, {
    key: 'getCanvas',
    value: function getCanvas() {
      if (this.client) {
        return this.client.getDisplay().getDefaultLayer().getCanvas();
      }
      return false;
    }

    /*
      GuacamoleWrapper.checkReady
       - polls to /info api call for checking if the task did finish
      - example:
         // poll
        client.checkReady(1, true, 'completed').then(ready => {
          if(ready) {
            console.log('vm is ready');
          } else {
            console.log('vm is not ready');
          }
        });
       - ID                = Number
      - poll              = true|false
      - pollUntillStatus  = "completed|reported"
       - returns: [ready{Bool},]
      */

  }, {
    key: 'checkReady',
    value: function checkReady(id) {
      var poll = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : false;
      var pollUntillStatus = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : 'completed';


      var iv = null;

      // the verification call as a promise
      var readyCall = function readyCall() {
        return new Promise(function (resolve, reject) {

          try {

            $.ajax({
              url: '/analysis/api/tasks/info/',
              type: 'POST',
              dataType: 'json',
              contentType: "application/json; charset=utf-8",
              data: JSON.stringify({
                "task_ids": [id]
              }),
              success: function success(response, xhr) {
                if (response.status === true) {
                  var t = response.data[id];
                  // wait untill the file is reported
                  if (t.status === pollUntillStatus) {
                    resolve(true, t);
                  } else {
                    resolve(false, t);
                  }
                } else {
                  throw "ajax error";
                  return;
                }
              },
              error: function error(err) {
                throw err;
              }
            });
          } catch (err) {
            return reject(err);
          }
        });
      };

      if (poll === true) {
        return new Promise(function (resolve, reject) {
          var iv = setInterval(function () {
            readyCall().then(function (result) {
              if (result === true) {
                iv = clearInterval(iv);
                return resolve(result);
              }
            }, function (err) {
              return reject(err);
            });
          }, 1000);
        }).catch(function (e) {
          return console.log(e);
        });
      } else {
        // return the promise
        return readyCall();
      }
    }
  }]);

  return GuacamoleWrapper;
}(_Hookable3.default);

exports.default = GuacamoleWrapper;

},{"./Hookable":2}],2:[function(require,module,exports){
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

},{}],3:[function(require,module,exports){
'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.RDPRender = undefined;

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

var _Hookable = require('./Hookable');

var _Hookable2 = _interopRequireDefault(_Hookable);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

function parseFragment(fragment) {
  var parsejQuery = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : true;

  if (!fragment.length) return false;
  var result = fragment.html();
  return parsejQuery ? $(result) : result;
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

/*
  The error state is not really a dialog, but this class will take care of rendering
  an error inside the viewport as a substitute class.
 */

var RDPRender = function () {
  function RDPRender(client, template) {
    _classCallCheck(this, RDPRender);

    this.client = client;
    this.template = parseFragment(template);
    this.active = false;
  }

  _createClass(RDPRender, [{
    key: 'render',
    value: function render() {
      if (!this.template) return;
      this.client.$.find('.rdp-app__viewport').html(this.template);
      this.active = true;
    }
  }, {
    key: 'destroy',
    value: function destroy() {
      this.template.remove();
    }
  }]);

  return RDPRender;
}();

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
    this.onClose = null;
    this.beforeRender = null;

    this.selector = null;
  }

  _createClass(RDPDialog, [{
    key: 'render',
    value: function render(d) {
      var opts = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : {};


      // don't render if a dialog is already open
      if (this.isOpen) return;

      // attach onClose handler
      if (opts.onClose && opts.onClose instanceof Function) {
        this.onClose = opts.onClose;
      }

      // attach beforeRender handler
      if (opts.beforeRender && opts.beforeRender instanceof Function) {
        this.beforeRender = opts.beforeRender;
      }

      var dialog = this.dialogs[d];

      if (dialog) {
        var ctx = parseFragment(dialog.template);
        if (this.beforeRender) this.beforeRender();
        this.base.find('.rdp-dialog__body').append(ctx);
        this.interaction = new DialogInteractionScheme(this, dialog);
        this._injectModel(this.interaction.model);
        this.open();

        // runs a callback after render for anything related.
        if (dialog.render) dialog.render(this, this.interaction);
      }

      return dialog;
    }

    // opens the dialog

  }, {
    key: 'open',
    value: function open() {
      if (!this.isOpen) {
        this.client.$.addClass('dialog-active');
        this.base.attr('open', true);
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
      var _this2 = this;

      if (this.onClose) {
        setTimeout(function () {
          _this2.onClose();
          _this2.onClose = null;
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

// export other functions


exports.default = RDPDialog;
exports.RDPRender = RDPRender;

},{"./Hookable":2}],4:[function(require,module,exports){
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

      var template = $('\n      <li data-snapshot-id="' + s.id + '">\n        <figure><img src="' + s.data + '" alt="snapshot" /></figure>\n        <div class="rdp-snapshots--controls">\n          <a href="snapshot:remove"><i class="fa fa-remove"></i></a>\n        </div>\n      </li>\n    ');

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
  this.data = null;
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
      var image = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : "";


      if (this.locked || image.length == 0) return;

      var s = new Snapshot(this.count);
      s.data = image;
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
  }, {
    key: 'capture',
    value: function capture(canvas) {
      return this.client.service.getCanvas().toDataURL();
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
          (function () {
            var id = parseInt(t.val());
            var snapshot = _this4.service.snapshots.find(function (s) {
              return s.id == id;
            });
            _this4.dispatchHook('selected', snapshot);
          })();
        } else {
          _this4.dispatchHook('deselected');
        }
      });

      _this4.on('selected', function (snapshot) {
        return _this4.selected.push(snapshot);
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

        var template = $('\n        <li>\n          <label for="snapshot-' + snapshot.id + '">\n            <input type="checkbox" name="snapshot-selection[]" value="' + snapshot.id + '" id="snapshot-' + snapshot.id + '" />\n            <span class="snapshot-selection-image">\n              <img src="' + snapshot.data + '" alt="snapshot-' + snapshot.id + '" />\n            </span>\n          </label>\n        </li>\n      ');

        this.el.find('ul').append(template);
      }

      return done();
    }
  }, {
    key: 'commit',
    value: function commit() {
      var _this5 = this;

      return new Promise(function (resolve, reject) {

        var data = _this5.selected;

        $.ajax({
          url: '/analysis/' + _this5.service.client.id + '/control/screenshots/',
          type: 'POST',
          dataType: 'json',
          contentType: "application/json; charset=utf-8",
          data: JSON.stringify(data),
          success: function success(response, xhr) {
            resolve();
          },
          error: function error(err) {
            reject(err);
          }
        });
      });
    }
  }]);

  return RDPSnapshotSelector;
}(_Hookable5.default);

exports.RDPSnapshotService = RDPSnapshotService;
exports.RDPSnapshotSelector = RDPSnapshotSelector;

},{"./Hookable":2}],5:[function(require,module,exports){
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
      control: new _RDPToolbarButton.RDPToolbarButton(client.$.find('button[name="control"]'), { client: client, holdToggle: true })
    };

    // toggle fullscreen mode
    _this.buttons.fullscreen.on('click', function () {
      if (CuckooWeb.isFullscreen()) {
        CuckooWeb.exitFullscreen();
      } else {
        CuckooWeb.requestFullscreen(document.getElementById('rdp-client'));
      }
    });

    // make a slight change to the client style to fit into viewport after a
    // change of fullscreen-ness.
    CuckooWeb.onFullscreenChange(function (e) {
      return _this.client.$.toggleClass('fullscreen', CuckooWeb.isFullscreen());
    });

    // snapshots
    _this.buttons.snapshot.on('click', function () {
      var image = _this.client.snapshots.capture();
      _this.client.snapshots.create(image);
    });

    // toggles control modes
    _this.buttons.control.on('toggle', function (toggled) {
      if (toggled) {
        // enable mouse and keyboard
        _this.client.service.mouse(true);
        _this.client.service.keyboard(true);
      } else {
        // disable mouse and keyboard
        _this.client.service.mouse(false);
        _this.client.service.keyboard(false);
      }
    });

    $('body').on('keydown', function (e) {

      // prevent triggering when in ctrl/alt/shift key modes, usually reserved for browser actions or
      // OS UX, semantically that should never break so we should prevent it, as well.
      if (cmdKeyPressed(e)) return;

      // in 'control' mode, we do not do shortcut keys to prioritize keyboard interactions to the vm
      if (_this.buttons.control.toggled) return;

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

},{"./Hookable":2,"./RDPToolbarButton":6}],6:[function(require,module,exports){
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

},{"./Hookable":2}],7:[function(require,module,exports){
'use strict';

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

var _Hookable2 = require('./Hookable');

var _Hookable3 = _interopRequireDefault(_Hookable2);

var _GuacWrap = require('./GuacWrap');

var _GuacWrap2 = _interopRequireDefault(_GuacWrap);

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
    _this.id = el.data('taskId');

    // alias internal
    var self = _this;
    var taskId = _this.id;

    // connect guac service wrapper
    _this.service = new _GuacWrap2.default({
      display: el.find('#guacamole-display'),
      client: _this
    });

    _this.snapshots = new _RDPSnapshotService.RDPSnapshotService(_this);
    _this.toolbar = new _RDPToolbar2.default(_this);

    // defines the UI dialogs
    _this.dialog = new _RDPDialog2.default(_this, {
      el: el.find('#rdp-dialog'),
      dialogs: {
        snapshots: {
          template: $("template#rdp-dialog-snapshots"),
          model: {
            total: function total() {
              return _this.snapshots.total();
            }
          },
          interactions: {
            cancel: function cancel(dialog) {
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
              dialog.selector.commit().then(function () {
                dialog.close();
              }, function (err) {
                console.log(err);
              });
            });

            dialog.selector.on('selected', updateSelected);
            dialog.selector.on('deselected', updateSelected);
          }
        },
        completed: {
          template: $("template#rdp-dialog-completed"),
          interactions: {
            close: function close(dialog) {
              // the module was rendered in a new tab, closing this page
              // should take us back to the postsubmit page if still opened.
              window.close();
            },
            report: function report(dialog) {
              window.location = '/analysis/' + taskId + '/summary/';
            }
          }
        }
      }
    });

    // several other 'specific' views, controlled by an 'RDPRender' class.
    // this class resembles a simple method for spawning different custom views
    // into the viewport.
    _this.errorDialog = new _RDPDialog.RDPRender(_this, $("template#rdp-error"));
    _this.connectingDialog = new _RDPDialog.RDPRender(_this, $("template#rdp-connecting"));

    // show the connection dialog
    _this.connectingDialog.render();

    // bind snapshot interactions
    _this.snapshots.on('create', function (snapshot) {
      _this.toolbar.buttons.snapshot.update();
    });

    _this.snapshots.bar.on('removed', function () {
      _this.toolbar.buttons.snapshot.update(true);
    });

    // initialize service wrapper, wrapped in a timeout to give the UI
    // a little time to configure itself.
    setTimeout(function () {

      _this.service.connect();

      _this.service.on('ended', function () {
        _this.toolbar.disable();
        el.find('.rdp-status').addClass('done');
        // if(this.snapshots.total() > 0) {
        //   let sd = this.dialog.render('snapshots', {
        //     onClose: () => self.dialog.render('completed')
        //   });
        // } else {
        //   this.dialog.render('completed', {
        //     beforeRender: () => self.errorDialog ? self.errorDialog.destroy() : function(){}
        //   });
        // }
      });

      // start polling for status updates to cling onto
      _this.service.checkReady(_this.id, true, 'reported').then(function (isReady, task) {

        if (isReady === true) {
          // IF SNAPSHOTS, SHOW SNAPSHOT DIALOG, THOUGH
          if (_this.snapshots.total() > 0) {
            var sd = _this.dialog.render('snapshots', {
              onClose: function onClose() {
                return self.dialog.render('completed');
              }
            });
          } else {
            _this.dialog.render('completed', {
              beforeRender: function beforeRender() {
                return self.errorDialog ? self.errorDialog.destroy() : function () {};
              }
            });
          }
        }
      }).catch(function (e) {
        return console.log(e);
      });

      // error handler for service wrapper
      _this.service.on('error', function () {
        _this.errorDialog.render();
      });
    }, 1500);

    _this.commonBindings();

    return _this;
  }

  // common bindings for non-complicated controls (such as toggling, etc.)


  _createClass(RDPClient, [{
    key: 'commonBindings',
    value: function commonBindings() {
      var _this2 = this;

      // property dropdown init
      var showProperties = function showProperties() {

        var isOpen = false;

        _this2.$.find('#toggle-properties').bind('click', function (e) {
          e.preventDefault();
          $(e.currentTarget).toggleClass('active', !isOpen);
          isOpen = $(e.currentTarget).hasClass('active');
        });

        $('body').bind('click', function (e) {
          var el = $(e.target);
          var partOfDetails = el.parents('.rdp-details').length > 0;

          if (isOpen && !partOfDetails) {
            _this2.$.find('#toggle-properties').trigger('click');
          }
        });
      };

      showProperties();
    }
  }]);

  return RDPClient;
}(_Hookable3.default);

// initialize the classes and construct the interface


$(function () {
  if ($("#rdp-client").length) {
    var rdpClient = new RDPClient($("#rdp-client"));
  }
});

},{"./GuacWrap":1,"./Hookable":2,"./RDPDialog":3,"./RDPSnapshotService":4,"./RDPToolbar":5}]},{},[7])


//# sourceMappingURL=rdp.js.map
