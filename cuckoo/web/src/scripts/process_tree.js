// private general functions
function parseProcessData(scr) {
  if(!scr) return {};
  return JSON.parse(scr.text());
}

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

/*
  Constructor class for the entire behavior tree, with all its views inside it.
 */
class ProcessBehaviorView {

  constructor(el) {
    this._$ = el;
    this._tree = new Tree(this._$.find('.tree'), 0);

    this.currentPage = 1;

    this.initialise();
  }

  initialise() {

    let self = this;

    // handle pane collapses
    this._$.find('.process-tree__header--right').bind('click', e => {

      e.preventDefault();
      let target = $(e.currentTarget);
      target.parents('.process-tree__tree, .process-tree__detail').toggleClass('open');

    });

    // enable bootstrap tooltips
    this._tree.el.find('[data-toggle="tooltip"]').tooltip({
      tooltipClass: 'cuckoo-tooltip tree-tip',
      position: { my: "left+20 top-20" },
      show: {
        effect: 'fade',
        duration: 100
      },
      hide: {
        effect: 'fade',
        duration: 100
      }
    });

    // handlers for loading data
    this._tree.el.find('[data-load]').bind('click', function(e) {
      e.preventDefault();
      self.loadChunk($(this)[0]);
    });

  }

  // gets called for loading api chunks
  loadChunk(el) {

    // parse to jquery, jquery seems to have a little trouble with es6 closure within
    // the context of a class.
    el = $(el);

    let self = this;
    let url = `/analysis/chunk/${window.task_id}/${el.data('load')}/${this.currentPage}`;

    // get some other data relevant to the chunk, such as name etc for the detail population. This is
    // right now configured as an in-app dump inside the target click handler, I would love to see
    // this switch to ajax in a near future.
    let data = parseProcessData(el.find('script'));

    $.get(url, res => {
      // renders the entire table
      self.renderTable(res);

      // populate meta aspects
      self._$.find('[data-placeholder="process-detail-pid"]').text(el.data('load'));
      self._$.find('[data-placeholder="process-detail-ppid"]').text(data.ppid);
      self._$.find('[data-placeholder="process-detail-name"]').text(data.name);
    });

  }

  // renders a table from the html string in the response.
  renderTable(plainTextResponse) {
    let table = $.parseHTML(plainTextResponse)[0];

    // re-style the table by setting classes
    $(table).removeClass('table table-bordered');
    $(table).addClass('cuckoo-table');

    // append to the detail body
    this._$.find('#behavior-table').html(table);

    // hide loading message, show table
    this._$.find('.loaded').slideDown();
    this._$.find('.unloaded').hide();
  }

}

// create 'trees' - debug only, later on this will merge into
// a controller class for the behavioral analysis page.
$(() => {

  if($("#behavior-process-tree").length) {
    let bpt = new ProcessBehaviorView($("#behavior-process-tree"));
  }

});
