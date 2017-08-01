/*
  A basic class definition for an element that has to be sticky
  when a user scrolls past it. This class will make sure everything is
  calculated nicely. Made in the first instance for handling sticky
  <thead> elements. But this should apply to any element.
 */
class Sticky {

  constructor(options = {}) {

    this.config = $.extend({
      el: null, // a jQuery element
      parent: $(window), // a scrollable parent of the sticky element
      offset: 0, // a constant parameter that takes in account any margins in the calculation
      useObserver: (window.MutationObserver !== undefined) // auto-bool based on existence by default
    }, options);

    this.elTopOffset = 0;
    this.observer = null;

    this.initialise();

  }

  initialise() {

    let self    = this;
    let el      = this.config.el;
    let parent  = this.config.parent;

    // calculates the offset to the top from the target element
    this.calculate();

    // binds a scroll event
    parent.bind('scroll.Sticky', e => {
      self.update(e);
    });

    if(MutationObserver && this.config.useObserver) {

      // experimental: use a MutationObserver to listen to DOM changes to update
      // the current top offset parameters
      this.observer = new MutationObserver(mutations => {
        self.calculate();
      });

      this.observer.observe(self.config.parent[0], {
        attributeFilter: ['class'],
        subtree: true
      });

    }

  }

  // updates every scroll trigger
  update(e) {

    let scrollTop = $(e.currentTarget).scrollTop();
    let diff = scrollTop - this.elTopOffset;

    if(scrollTop > this.elTopOffset) {
      this.config.el.css('transform', `translateY(${diff}px)`);
    } else {
      this.config.el.css('transform', 'translateY(0px)');
    }

  }

  // calculates the current offset of the element
  calculate() {
    this.elTopOffset = this.config.el.offset().top - this.config.offset;
  }

  // unsticks this element
  unstick() {
    this.config.parent.unbind('scroll.Sticky');
    this.observer.disconnect();
  }

}
