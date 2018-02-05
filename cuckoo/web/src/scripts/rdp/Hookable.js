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
const noop = () => true;

// hookable class wrapper
export default class Hookable {

  constructor() {
    this.hooks = {};
  }

  // subscribes a hook
  on(evt, cb = noop) {
    // create hook entry
    if(!this.hooks[evt]) this.hooks[evt] = [];
    this.hooks[evt].push(cb);
    return this;
  }

  // runs a hook cycle
  dispatchHook(evt = '', data = {}) {
    if(this.hooks[evt]) {
      this.hooks[evt].forEach(hook => {
        if(hook instanceof Function) {
          hook.call(this, data);
        }
      });
    }
    return this;
  }

}
