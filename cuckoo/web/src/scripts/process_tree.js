/*
  Interface controller for a 'tree'. This piece works with
  a list-in-list HTML definition with at least the following
  syntax:

  <ul data-tree="init">
    <li>
      <div>item <a data-tree="toggle">open</a></div>
      <ul>
        <li><div>item</div></li>
        <li><div>item</div></li>
        <li>
          <div>item <a data-tree="toggle"></a></div>
          <ul>
            <li><div>item</div></li>
            <li><div>item</div></li>
            ... and so forth.
          </ul>
        </li>
      </ul>
    </li>
  </ul>

  Actions can be bound inside the html with the data-tree
  attribute. Available:

  data-tree="toggle"
    - will expand/collapse the underlying <ul> element
      at the same level.

  data-tree="init"
    - will initialize a Tree onto the target <ul> element

  data-tree-initialized="true"
    - flag property to tell whether the tree already did
      initialzie. This way, we can always run Tree.init()
      to initialise un-initialized trees (if needed) without
      re-initializing existing ones.

  */
class Tree {

  /*
    Constructor
    @param el - Object [ jQuery selector ]
    @param id - a numbder index
    */
  constructor(el, id) {

    // class properties
    this.el = el;
    this.index = id;

    // add initialized class
    el.attr('data-tree-initialized', true);

    // create the tree
    this.setup();
  }

  // creates the tree
  setup() {

    let self = this;

    // bind the toggles
    this.el.find('[data-tree="toggle"]').bind('click', e => {
      e.preventDefault();
      self.toggleBranch($(e.currentTarget));
    });

    this.el.addClass('open');

  }

  // branch toggle handler, will decide whether to open or close an element.
  toggleBranch($toggle) {

    // select the list
    let targetList = $toggle.closest('li').children('ul');

    // toggle the 'open' class
    targetList.toggleClass('open');
    $toggle.toggleClass('is-open', targetList.hasClass('open'));

  }

}

// create 'trees' - debug only, later on this will merge into
// a controller class for the behavioral analysis page.
$(() => {
  $('.tree').each(function(i) {
    if(!$(this).attr('data-tree-initialized')) {
      var tree = new Tree($(this), i);
      $(this).data('tree', tree);
    }
  });
});
