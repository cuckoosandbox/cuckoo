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

// will deprecate
var feedbackFormSubmitted = false;

function send_button_toggle() {

  var sel = $('#modal_feedback');

  sel.find("input#submit").toggleClass('sending');

  if (sel.find('input#submit').hasClass('sending')) {
    sel.find('input#submit').attr('disabled', true);
    $("#modal_feedback").find("#result").html('Sending feedback... a moment.');
  } else {
    sel.find('input#submit').attr('disabled', false);
  }
}

// will deprecate
function feedback_send(task_id, name, email, company, message, include_analysis, include_memdump, callback) {

  var params = {
    "task_id": task_id,
    "email": email,
    "message": message,
    "name": name,
    "company": company,
    "include_memdump": include_memdump,
    "include_analysis": include_analysis
  };

  CuckooWeb.api_post("/analysis/api/task/feedback_send/", params, function (data) {
    callback(data);
  }, function (err) {
    if (err.responseJSON.hasOwnProperty("message")) {
      var _message = err.responseJSON.message;
      $("#modal_feedback").find("#result").html(_message);
      send_button_toggle();
      feedbackFormSubmitted = false;
    }
  });
}

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
      "task_id": task_id,
      "email": null,
      "message": null,
      "name": null,
      "company": null,
      "include_memdump": null,
      "include_analysis": null
    };

    // required fields
    this.required = ["name", "email", "company", "message"];

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
        console.log(data);
        _this.reset();
        _this.close();
      }, function (err) {
        console.log(err);
        _this.displayError(err.responseJSON ? err.responseJSON.message : false);
      }, function () {
        _this.el.find('button[type="submit"]').prop('disabled', false);
        _this.el.find('button[type="submit"]').text('Send feedback report');
      });
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
        always();
      }
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
  }]);

  return FeedbackForm;
}();

// instantiate the feedback form


$(function () {
  if ($(".modal-cuckoo#feedback_form").length) {
    var form = new FeedbackForm($(".modal-cuckoo#feedback_form form"));
    form.open();
  }
});
//# sourceMappingURL=analysis_feedback.js.map
