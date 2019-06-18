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
      e.stopPropagation();
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

  // opens all tree items
  toggleAll(open = true) {
    let toggles = this.el.find('[data-tree="toggle"]');
    toggles.closest('li').children('ul').toggleClass('open', open);
    toggles.toggleClass('is-open', open);
  }

}

/*
  PaginationBar
*/
class PaginationBar {

  constructor(options) {

    // extend options with default config parameters
    this.config = $.extend({
      container: null,
      currentPage: 1,
      totalPages: 40,
      display: 20,
      onPaginate: function() { return this; }
    }, options);

    // dom element assignment
    this.$ = null;

    // render the bar
    this.render();

  }

  // renders the pagination bar in the container, if a container is not set,
  // this will output the html instead.
  render() {

    var config  = this.config;
    var html    = $("<ul />");

    // creates a page item
    function _page(n) {
      var $page = $("<li />");
      var $link = $("<a />");

      $link.text(n);

      if(n == config.currentPage) {
        $link.addClass('active');
      }

      if(!isNaN(n)) {
        $link.attr('href', `page:${n}`);
      }

      return $page.append($link);
    }

    // appends the first page
    html.append(_page(1));

    // adds a '...' item if we are out of sight for the first item
    if(config.currentPage-10 > 2) html.append(_page('...'));

    let pageMin = Math.max(2, config.currentPage-10);
    let pageMax = Math.min(config.totalPages, config.currentPage+10);

    for(
      var i  = pageMin;
          i <= pageMax;
          i++
    ) {

      var $page = _page(i);
      html.append($page);

    }

    // if we are not yet in the last results, we display a number with
    // the last page.
    if(config.currentPage+10 < config.totalPages) {
      html.append(_page('...'));
      html.append(_page(config.totalPages));
    }

    if(config.container) {
      config.container.html(html);
      this.bind(config.container);
    } else {
      return html;
    }

  }

  // binds click handlers to the pagination item links
  bind(pages) {

    let self = this;

    pages.find('a[href]').bind('click', function(e) {
      e.preventDefault();
      let page = $(this).attr('href').replace('page:','');
      self.goto(page);
    });

    this.$ = pages;
  }

  // goto function
  goto(n) {

    this.config.currentPage = parseInt(n);
    this.render();
    // fire callback
    this.config.onPaginate(n);
  }

  // destroys the element
  destroy() {
    this.$.empty();
  }

}

/*
  Constructor class for the entire behavior tree, with all its views inside it.
 */
class ProcessBehaviorView {

  constructor(el) {

    this._$      = el;
    this._tree   = new Tree(this._$.find('.tree'), 0);
    this._table  = null;
    this._bar    = null;
    this._tags   = this._$.find('.process-spec--tags');
    this._loader = null;
    this._sticky = null;
    this._search = this._$.find('.process-tree__search');

    // opens all items in the tree on init
    this._tree.toggleAll(true);

    // create the loader if we have the loader
    if(this._$.find('.loading').length) {
      this._loader = new Loader(this._$.find('.loading'), {
        animate: true,
        duration: 300
      });
      this._loader.stop();
    }

    this.currentPage = 1;
    this.currentPid = null;
    this.isLoadingSearch = false;

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
      self.loadChunk($(this).data('load'));
      self.populate($(this).find('script'));

      // reset the categories active state because we're loading a default dataset
      self._tags.children().removeClass('active');

      // toggle the selected class
      $(e.currentTarget).closest('.processes').find('.selected').removeClass('selected');
      $(e.currentTarget).closest('div').addClass('selected');

      // reset the current search state
      self._search.find('input').val('');
    });

    // connect the filtered api
    this._tags.find('[href^="filter:"]').bind('click', function(e) {
      e.preventDefault();

      // no pagination for this page, according to the previous version.
      if(self._bar) self._bar.destroy();
      self.loadChunk(self.currentPid, $(this).attr('href').split(':')[1]);

      // remove the current active classes
      $(this).parent().find('a').removeClass('active');

      // set an active class
      $(this).addClass('active');

    });

    // connect the search UI - submission
    this._search.find('button').bind('click', e => {
      self.search(self._search.find('input').val());
    });

    this._search.find('input').bind('keypress', e => {
      if(e.which == 13) {
        self.search(self._search.find('input').val());
      }
    });

    // loads the first item on init if there is a first item by emulating a click
    // that'll trigger the handler.
    var firstItem = this._tree.el.find('li:first > [data-load]');
    if(firstItem) {
      this._tree.el.find('li:first > [data-load]').trigger('click');
    }

  }

  // gets called for loading api chunks
  loadChunk(pid, filter) {

    // if we're loading a search query, disable chunk loading
    if(this.isLoadingSearch) return;

    // parse to jquery, jquery seems to have a little trouble with es6 closure within
    // the context of a class.

    var self = this,
        url = '';

    // set the current pid
    self.currentPid = pid;

    if(!filter) {
      url = `/analysis/chunk/${window.task_id}/${pid}/${this.currentPage}/`;
    } else {
      url = `/analysis/filtered/${window.task_id}/${pid}/${filter}/`;
    }

    if(url.length) {
      this._loader.start();
      $.get(url, res => {
        // stops the loader and renders the entire table
        self._loader.stop(() => {
          self.renderTable(res);
          self._tags.show();
        });
      });
    }

  }

  // does a search in the current PID
  search(query = "") {

    let self = this;

    // break out if we are already loading a search request
    if(this.isLoadingSearch) return;

    // only proceed if the conditions are good for search
    if(window.task_id && query) {

      this.isLoadingSearch = true;
      this._$.addClass('searching');
      this._search.find('button').addClass('loading');
      this._tree.el.find('.selected').removeClass('selected'); // deselects selected pid

      let url = `/analysis/search/${window.task_id}/`;

      CuckooWeb.post(url, {
        search: query
      }, function(response) {

        self.isLoadingSearch = false;
        self._search.find('button').removeClass('loading');

        // do some search UI specific things
        self._$.find('[data-placeholder="process-detail-name"]').html(`<span><i class="fa fa-search"></i> ${query}</span>`);
        self._$.find('.process-spec--name table').hide();
        self._tags.hide();

        // auto-close process tree because the results are gathered amongst all
        // processes and therefore the tree is not of use using the search.
        self._$.find('.process-tree__tree').removeClass('open');

        // render the table
        self._$.removeClass('searching');
        self.renderTable(response, true);
      });

    } else {
      console.error('Task ID and query required for searching. Aborting search.');
    }
  }

  // populates information about the current process
  populate(el) {
    let data = parseProcessData(el);
    this._$.find('[data-placeholder="process-detail-pid"]').text(data.pid);
    this._$.find('[data-placeholder="process-detail-ppid"]').text(data.ppid);
    this._$.find('[data-placeholder="process-detail-name"]').text(data.name);
    this._$.find('.process-spec--name table').show();

    // get the current total pages from the static rendered pagination info script tag
    // and only render the bar if we have this info
    this.renderBar(data.pid, 1);

}

  // renders a table from the html string in the response.
  // - handles regular chunks, filtered chunks and search chunks
  renderTable(plainTextResponse, search = false) {

    let self = this;
    let table = $.parseHTML(plainTextResponse)[0];
    let sticky = null;

    // for search, dive deeper in the HTML to find the table
    if(search) {
      table = $(table).find('table');
      table.addClass('behavior-search-results');
    }

    let tableColumns = $(table).find('thead th').length;
    let tableChildren = $(table).find('tbody').children();
    let noResultCell = null;

    // re-style the table by setting classes
    $(table).removeClass('table table-bordered');
    $(table).addClass('cuckoo-table');

    // handle empty result sets
    if(tableChildren.length == 0) {
      noResultCell = $(`<tr>
                        <td colspan="${tableColumns}" class="no-result">
                          <p>No results</p>
                          <button class="button">Reset filter</button>
                        </td>
                      </tr>`);

      $(table).append(noResultCell);

      noResultCell.find('button').bind('click', function() {
        if(self.currentPid) {
          self._tags.find('.active').removeClass('active'); // reset active class
          self.loadChunk(self.currentPid); // load currentPid
        }
      });
    }

    // append to the detail body
    this._$.find('#behavior-table').html(table);

    // hide loading message, show table
    this._$.find('.loaded').slideDown();

    // hide the 'unloaded' message
    this._$.find('.unloaded').hide();

    // a bundle of search-specific table interactions
    if(search) {

      // destroy any pagination bars appended
      if(this._bar) this._bar.destroy();

      table.find('[data-represent]').bind('click', e => {
        e.preventDefault();
        $(e.currentTarget).toggleClass('collapsed');
        $(e.currentTarget).closest('table').find(`[data-belongs-to="${$(e.currentTarget).data('represent')}"]`).toggleClass('hidden');
      });

    }

    if(Sticky) {

      if(this._sticky) this._sticky.unstick();

      this._sticky = new Sticky({
        el: $(table).find('thead'),
        parent: $(".flex-nav__body"),
        offset: $('#primary-nav').height() + 20
      });
    }

    // reference current table to constructor
    this._table = table;

  }

  // renders the pagination bar
  renderBar(pid, current) {

    let self = this;

    // reset inner flags
    this.currentPage = current;

    if(this._bar) this._bar.destroy();

    // create a new bar
    this._bar = new PaginationBar({
      totalPages: window.PROCESS_TREE_PAGINATION_INFO[pid],
      container: self._$.find('.process-spec--pagination'),
      onPaginate: function(page) {
        self.currentPage = page;
        self.loadChunk(pid);
      }
    });

  }

}

// boot up the view class for the behavior controller
$(() => {

  if($("#behavior-process-tree").length) {
    let bpt = new ProcessBehaviorView($("#behavior-process-tree"));
  }

});
