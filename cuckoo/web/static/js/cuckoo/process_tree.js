"use strict";

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

/*
  Interface controller for a 'tree'. This piece works with
  a list-in-list HTML definition with at least the following
  syntax:

  <ul>
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

  */
var Tree = function Tree() {
  _classCallCheck(this, Tree);
};
//# sourceMappingURL=process_tree.js.map
