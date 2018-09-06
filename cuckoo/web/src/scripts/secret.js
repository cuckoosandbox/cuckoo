window.addEventListener('DOMContentLoaded', e => {

  const modal  = document.querySelector('.modal-cuckoo');
  const form   =    modal.querySelector('form.modal-dialog');
  const secret =     form.querySelector('input#cuckoo-secret');

  form.addEventListener('submit', e => {
    e.preventDefault();
    console.log('lets verify that key.');
  });

});
