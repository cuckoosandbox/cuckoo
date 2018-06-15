'use strict';

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

/*
 * Copyright (C) 2010-2013 Claudio Guarnieri.
 * Copyright (C) 2014-2016 Cuckoo Foundation.
 * This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
 * See the file 'docs/LICENSE' for copying permission.
 *
 */

// a simple wrapper around the feedback functionality
var FeedbackForm = function () {
  function FeedbackForm(el) {
    var _this = this;

    _classCallCheck(this, FeedbackForm);

    if (!el) {
      console.log('no element applied. Feedback form cannot be used.');
      return;
    }

    this.el = el;
    this.modal = this.el.parents('.modal');

    // default set of params
    this.params = {
      "task_id": task_id || false,
      "email": false,
      "message": false,
      "name": false,
      "company": false,
      "include_memdump": false,
      "include_analysis": false

      // required fields
    };this.required = ["name", "email", "company", "message"];

    // updates the inner params
    this.el.find('input,select,textarea').bind('change', function (e) {
      _this.update();
    });

    // submits the form
    this.el.on('submit', function (e) {

      e.preventDefault();

      _this.resetError();
      _this.el.find('button[type="submit"]').prop('disabled', true);
      _this.el.find('button[type="submit"]').text('Sending...');

      _this.send(function (data) {
        _this.reset();
        _this.close();
      }, function (err) {
        _this.displayError(err.responseJSON ? err.responseJSON.message : false);
      }, function () {
        _this.el.find('button[type="submit"]').prop('disabled', false);
        _this.el.find('button[type="submit"]').text('Send feedback report');
      });
    });

    if (!task_id) {
      this.params.task_id = false;
      this.params.include_memdump = false;
      this.params.include_analysis = false;
      // hide feedback includes and feedback report size when there is no task
      // id.
      this.modal.find('#feedback-includes, #feedback-size').remove();
      this.modal.find('.modal-form:last-child').prev().addClass('arrow-center');
    }

    // update on init
    this.update();

    // re-estimate each time
    this.changed(['include_analysis', 'include_memdump'], function (value) {
      _this.estimate();
    });

    // do a pre-estimate
    this.estimate();

    // cancel the feedback form
    this.modal.find('[href="modal:cancel"]').bind('click', function (e) {
      e.preventDefault();
      _this.cancel();
    });
  }

  // updates params


  _createClass(FeedbackForm, [{
    key: 'update',
    value: function update() {
      var self = this;
      this.el.find('input,select,textarea').each(function (i) {
        if (self.params.hasOwnProperty($(this).attr('name'))) {
          var value = $(this).val();
          if ($(this).attr('type') !== 'checkbox') {
            self.params[$(this).attr('name')] = $(this).val() || false;
          } else {
            self.params[$(this).attr('name')] = $(this).is(':checked');
          }
        }
      });
    }

    // validates params

  }, {
    key: 'validate',
    value: function validate() {
      var validated = true;
      for (var req in this.required) {
        if (!this.params[this.required[req]]) {
          validated = false;
          this.el.find('[name=\'' + this.required[req] + '\']').parent().addClass('error');
        } else {
          this.el.find('[name=\'' + this.required[req] + '\']').parent().removeClass('error');
        }
      }
      return validated;
    }

    // sends the data to the backend after validation

  }, {
    key: 'send',
    value: function send() {
      var then = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : function () {};
      var nope = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : function () {};
      var always = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : function () {};

      var validated = this.validate();
      if (validated) {
        CuckooWeb.api_post("/analysis/api/task/feedback_send/", this.params, function (data) {
          then(data);
          always();
        }, function (err) {
          nope(err);
          always();
        });
      } else {
        this.displayError('Please fill out all the required fields.');
        always();
      }
    }

    // a file inclusion estimation

  }, {
    key: 'estimate',
    value: function estimate() {
      var _this2 = this;

      var self = this;

      if (!self.params.task_id) {
        return;
      }

      var analysis = this.params.include_analysis;
      var memory = this.params.include_memdump;

      this.el.find('.file-estimation').text('estimating...');
      this.el.find('[name="include_analysis"],[name="include_memdump"]').prop('disabled', true);

      /*
        I believe underneath code can be done much better backend-wise. Does
        it really need the backend in the first place here?
       */

      // get files
      CuckooWeb.api_post("/analysis/api/task/export_get_files/", {
        task_id: self.params.task_id
      }, function (data) {

        if (data.dirs) {
          var dirs = [];
          data.dirs = data.dirs.map(function (obj, i) {
            // skip 'memory' if include_memdump is toggled to false
            if (obj[0] == "memory" && !memory) return false;
            // don't include anything at all if we disabled analysis
            if (!analysis) return false;
            dirs.push(obj[0]);
          });
          data.dirs = dirs;
        }

        CuckooWeb.api_post("/analysis/api/task/export_estimate_size/", {
          task_id: self.params.task_id,
          dirs: data.dirs,
          files: data.files
        }, function (estimation) {
          _this2.el.find('.file-estimation').text(estimation.size_human);
          _this2.el.find('[name="include_analysis"],[name="include_memdump"]').prop('disabled', false);
        });
      });
    }

    // displays an error

  }, {
    key: 'displayError',
    value: function displayError() {
      var message = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : 'Something went wrong';

      this.modal.find('.modal-footer').text(message);
      this.modal.find('.modal-footer').prev().addClass('arrow arrow-center');
    }

    // resets an error

  }, {
    key: 'resetError',
    value: function resetError() {
      this.modal.find('.modal-footer').prev().removeClass('arrow arrow-center');
      this.modal.find('.modal-footer').text('');
    }

    // UI controls

  }, {
    key: 'open',
    value: function open() {
      this.modal.modal('show');
    }
  }, {
    key: 'close',
    value: function close() {
      this.reset();
      this.modal.modal('hide');
    }
  }, {
    key: 'reset',
    value: function reset() {
      this.el.find('input, textarea').val("");
      this.update();
    }
  }, {
    key: 'cancel',
    value: function cancel() {
      this.reset();
      this.close();
    }

    // this is a very small event handler on changed fields to interact
    // quickly with them.

  }, {
    key: 'changed',
    value: function changed() {
      var _this3 = this;

      var paramName = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : false;
      var cb = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : function () {};

      if (!(paramName instanceof Array)) {
        this.el.find('[name=\'' + paramName + '\']').bind('change', function (e) {
          cb(_this3.params[paramName]);
        });
      } else {
        var _loop = function _loop(p) {
          _this3.el.find('[name=\'' + paramName[p] + '\']').bind('change', function (e) {
            cb(_this3.params[paramName[p]]);
          });
        };

        for (var p in paramName) {
          _loop(p);
        }
      }
    }
  }]);

  return FeedbackForm;
}();

// instantiate the feedback form


$(function () {

  // add an extra class to the backdrop to make it blue.
  $(".modal-cuckoo").on('show.bs.modal', function (e) {
    setTimeout(function () {
      $(".modal-backdrop").addClass('modal-cuckoo-backdrop');
    }, 50);
  }).on('hidden.bs.modal', function () {
    $(".modal-backdrop").removeClass('modal-cuckoo-backdrop');
  });

  if ($(".modal-cuckoo#feedback_form").length) {
    var form = new FeedbackForm($(".modal-cuckoo#feedback_form form"));
  }
});
//# sourceMappingURL=analysis_feedback.js.map
