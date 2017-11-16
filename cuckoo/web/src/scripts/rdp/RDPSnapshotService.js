import Hookable from './Hookable';

class SnapshotBar extends Hookable {
  constructor(el, service) {
    super();

    this.$ = el;
    this.service = service;
    this.hooks = {
      'added': [],
      'removed': []
    }

  }

  // adds an item to the bar
  add(s) {

    let template = $(`
      <li data-snapshot-id="${s.id}">
        <figure><img src="/static/graphic/screenshot-sample.png" alt="snapshot" /></figure>
        <div class="rdp-snapshots--controls">
          <a href="snapshot:remove"><i class="fa fa-remove"></i></a>
        </div>
      </li>
    `);

    // append this to the list
    this.$.prepend(template);
    this.dispatchHook('added', template);

    template.find('a[href="snapshot:remove"]').bind('click', e => {
      e.preventDefault();
      this.service.remove(template.data('snapshotId'));
      template.remove();
      this.dispatchHook('removed');
    });
  }

}

class Snapshot {
  constructor(id) {
    this.id = id;
  }
}

class RDPSnapshotService extends Hookable {
  constructor(client) {
    super();

    this.client = client;
    this.snapshots = [];
    this.bar = new SnapshotBar(this.client.$.find('#rdp-snapshot-collection'), this);
    this.count = 0;

    this.hooks = {
      create: [],
      remove: []
    }

  }

  create() {
    let s = new Snapshot(this.count);
    this.snapshots.push(s);
    this.count = this.count+1;
    this.bar.add(s);
    this.dispatchHook('create', s);
  }

  remove(id) {
    let pos = false;

    this.snapshots.forEach((snapshot, index) => {
      if(snapshot.id == id) pos = index;
    });

    if(pos !== false) {
      this.snapshots.splice(pos, 1);
    }

    this.dispatchHook('remove', {});
  }

  total() {
    return this.snapshots.length;
  }

}

// a class for handling the selection, for now somewhat specific maybe
// but this will work for now.
class RDPSnapshotSelector extends Hookable {

  constructor(el, service) {

    super();

    this.el        = el; // should be a form
    this.snapshots = [];
    this.selected  = [];
    this.service   = service || null;

    this.hooks = {
      submit: [],
      selected: [],
      deselected: []
    };

    this.populate(() => {

      this.el.on('submit', e => {
        e.preventDefault();
        this.dispatchHook('submit', this.selected);
      });

      this.el.find('input[type="checkbox"]').bind('change', e => {
        let t = $(e.currentTarget);
        if(t.is(':checked')) {
          this.dispatchHook('selected');
        } else {
          this.dispatchHook('deselected');
        }
      });

      this.on('selected', () => this.selected.push({}));
      this.on('deselected', () => this.selected.pop());

    });

  }

  // populates the selection list
  populate(done = function(){}) {

    if(!this.service) return done();

    for(let s in this.service.snapshots) {

      let snapshot = this.service.snapshots[s];

      let template = $(`
        <li>
          <label for="snapshot-${snapshot.id}">
            <input type="checkbox" name="snapshot-selection[]" value="1" id="snapshot-${snapshot.id}" />
            <span class="snapshot-selection-image">
              <img src="/static/graphic/screenshot-sample.png" alt="snapshot-${snapshot.id}" />
            </span>
          </label>
        </li>
      `);

      this.el.find('ul').append(template);

    }

    return done();

  }

}

export { RDPSnapshotService, RDPSnapshotSelector };
