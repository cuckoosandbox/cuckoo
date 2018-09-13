'use strict';

window.addEventListener('DOMContentLoaded', function (e) {

  var state = {
    form_submitted: false
  };

  var modal = document.querySelector('.modal-cuckoo');
  var form = modal.querySelector('form.modal-dialog');
  var secret = form.querySelector('input#secret');
  var smsg = secret.parentNode.querySelector('label .input-message');
  var action = modal.querySelectorAll('a[href^="action:"]');
  var more = modal.querySelector('[data-toggleable-col]');
  var effect = document.querySelectorAll('.effect');

  var actions = {
    leave: function leave() {
      return window.close();
    },
    'toggle-info': function toggleInfo(el) {
      more.classList.toggle('hidden', !more.classList.contains('hidden'));
      if (more.classList.contains('hidden')) {
        el.classList.replace('variation-blue', 'variation-grey');
      } else {
        el.classList.replace('variation-grey', 'variation-blue');
      }
    }
  };

  // easy-fied action toggling
  [].forEach.call(action, function (link) {
    link.addEventListener('click', function (e) {
      e.preventDefault();
      var target = e.currentTarget.href.split(':')[1];
      if (actions[target]) actions[target](e.currentTarget);
    });
  });

  // appends a message to the input label
  function handleInvalidInput() {
    var message = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : "";

    smsg.textContent = message;
  }

  // forcibly prevent HTML5 'required' popup to not show, we will handle this ourself.
  secret.addEventListener('invalid', function () {
    return function (e) {
      e.preventDefault();
      handleInvalidInput('You have to enter a key. This field is empty.');
      secret.focus();
    };
  }(), true);

  // validates the user input / processes the input
  form.addEventListener('submit', function (e) {

    if (!state.form_submitted) {
      e.preventDefault();
      state.form_submitted = true;
      // perform any pre-submit validations here
      var value = secret.value;
      if (!value.length) {
        state.form_submitted = false;
      } else {
        // submit the form without the !form_submitted condition, this will
        // actually start the POST submission.
        form.submit();
      }
      return;
    }
  });

  // run the wooshies
  [].forEach.call(effect, function (eff) {
    setTimeout(function () {
      eff.classList.remove('effect-slide-hold');
      eff.classList.remove('effect-fade-hold');
    }, 100);
  });
});
//# sourceMappingURL=secret.js.map
