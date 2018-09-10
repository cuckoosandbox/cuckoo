'use strict';

window.addEventListener('DOMContentLoaded', function (e) {

  var modal = document.querySelector('.modal-cuckoo');
  var form = modal.querySelector('form.modal-dialog');
  var secret = form.querySelector('input#cuckoo-secret');
  var smsg = secret.parentNode.querySelector('label .input-message');
  var action = modal.querySelectorAll('a[href^="action:"]');
  var more = modal.querySelector('[data-toggleable-col]');

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

  // validates the user input / processes the input
  form.addEventListener('submit', function (e) {
    e.preventDefault();
    var value = secret.value;
    if (!value.length) {
      handleInvalidInput('You have to enter a key. This field is empty.');
    } else {
      handleInvalidInput('This is not a good key.');
    }
  });
});
//# sourceMappingURL=secret.js.map
