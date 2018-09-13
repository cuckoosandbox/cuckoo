window.addEventListener('DOMContentLoaded', e => {

  const state   = {
    form_submitted: false
  };

  const modal   = document.querySelector('.modal-cuckoo');
  const form    = modal.querySelector('form.modal-dialog');
  const secret  = form.querySelector('input#cuckoo-secret');
  const smsg    = secret.parentNode.querySelector('label .input-message');
  const action  = modal.querySelectorAll('a[href^="action:"]');
  const more    = modal.querySelector('[data-toggleable-col]');

  const actions = {
    leave: () => window.close(),
    'toggle-info': el => {
      more.classList.toggle('hidden', !more.classList.contains('hidden'));
      if(more.classList.contains('hidden')) {
        el.classList.replace('variation-blue','variation-grey');
      } else {
        el.classList.replace('variation-grey','variation-blue');
      }
    }
  };

  // easy-fied action toggling
  [].forEach.call(action, link => {
    link.addEventListener('click', e => {
      e.preventDefault();
      let target = e.currentTarget.href.split(':')[1];
      if(actions[target]) actions[target](e.currentTarget);
    });
  });

  // appends a message to the input label
  function handleInvalidInput(message = "") {
    smsg.textContent = message;
  }

  // validates the user input / processes the input
  form.addEventListener('submit', e => {

    if(!state.form_submitted) {
      e.preventDefault();
      state.form_submitted = true;
      // perform any pre-submit validations here
      let value = secret.value;
      if(!value.length) {
        handleInvalidInput('You have to enter a key. This field is empty.')
        state.form_submitted = false;
      } else {
        // submit the form without the !form_submitted condition, this will
        // actually start the POST submission.
        form.submit();
      }
      return;
    }

  });

});
