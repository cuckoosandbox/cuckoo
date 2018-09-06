'use strict';

window.addEventListener('DOMContentLoaded', function (e) {

  var modal = document.querySelector('.modal-cuckoo');
  var form = modal.querySelector('form.modal-dialog');
  var secret = form.querySelector('input#cuckoo-secret');

  form.addEventListener('submit', function (e) {
    e.preventDefault();
    console.log('lets verify that key.');
  });
});
//# sourceMappingURL=secret.js.map
