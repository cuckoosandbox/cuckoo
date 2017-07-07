'use strict';

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

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
var Tree = function () {

  /*
    Constructor
    @param el - Object [ jQuery selector ]
    @param id - a numbder index
    */
  function Tree(el, id) {
    _classCallCheck(this, Tree);

    // class properties
    this.el = el;
    this.index = id;

    // add initialized class
    el.attr('data-tree-initialized', true);

    // create the tree
    this.setup();
  }

  // creates the tree


  _createClass(Tree, [{
    key: 'setup',
    value: function setup() {

      var self = this;

      // bind the toggles
      this.el.find('[data-tree="toggle"]').bind('click', function (e) {
        e.preventDefault();
        self.toggleBranch($(e.currentTarget));
      });

      this.el.addClass('open');
    }

    // branch toggle handler, will decide whether to open or close an element.

  }, {
    key: 'toggleBranch',
    value: function toggleBranch($toggle) {

      // select the list
      var targetList = $toggle.closest('li').children('ul');

      // toggle the 'open' class
      targetList.toggleClass('open');
      $toggle.toggleClass('is-open', targetList.hasClass('open'));
    }
  }]);

  return Tree;
}();

/*
  Constructor class for the entire behavior tree, with all its views inside it.
 */


var ProcessBehaviorView = function () {
  function ProcessBehaviorView(el) {
    _classCallCheck(this, ProcessBehaviorView);

    this._$ = el;
    this._tree = new Tree(this._$.find('.tree'), 0);

    this.initialise();
  }

  _createClass(ProcessBehaviorView, [{
    key: 'initialise',
    value: function initialise() {

      // handle pane collapses
      this._$.find('.process-tree__header--right').bind('click', function (e) {

        e.preventDefault();
        var target = $(e.currentTarget);
        target.parents('.process-tree__tree, .process-tree__detail').toggleClass('open');
      });

      // enable bootstrap tooltips
      this._$.find('[data-toggle="tooltip"]').tooltip({
        placement: 'bottom left'
      });
    }
  }]);

  return ProcessBehaviorView;
}();

// create 'trees' - debug only, later on this will merge into
// a controller class for the behavioral analysis page.


$(function () {

  if ($("#behavior-process-tree").length) {
    var bpt = new ProcessBehaviorView($("#behavior-process-tree"));
  }
});
//# sourceMappingURL=process_tree.js.map
