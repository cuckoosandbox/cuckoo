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
        <figure><img src="${s.data}" alt="snapshot" /></figure>
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

      if(this.service.locked) return;

      this.service.remove(template.data('snapshotId'));
      template.remove();
      this.dispatchHook('removed');
    });
  }

}

class Snapshot {
  constructor(id) {
    this.id = id;
    this.data = null;
  }
}

class RDPSnapshotService extends Hookable {
  constructor(client) {
    super();

    this.client = client;
    this.snapshots = [];
    this.bar = new SnapshotBar(this.client.$.find('#rdp-snapshot-collection'), this);
    this.count = 0;
    this.locked = false;

    this.hooks = {
      create: [],
      remove: []
    }

  }

  create(image = "") {

    if(this.locked || image.length == 0) return;

    let s = new Snapshot(this.count);
    s.data = image;
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

  lock(isLocked = undefined) {
    if(isLocked === undefined) {
      // toggle if no property had been given
      this.locked = !!this.locked;
    } else {
      this.locked = isLocked;
    }

  }

  capture(canvas) {
    return this.client.service.getCanvas().toDataURL();
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
          let id = parseInt(t.val());
          let snapshot = this.service.snapshots.find(s => s.id == id);
          this.dispatchHook('selected', snapshot);
        } else {
          this.dispatchHook('deselected');
        }
      });

      this.on('selected', snapshot => this.selected.push(snapshot));
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
            <input type="checkbox" name="snapshot-selection[]" value="${snapshot.id}" id="snapshot-${snapshot.id}" />
            <span class="snapshot-selection-image">
              <img src="${snapshot.data}" alt="snapshot-${snapshot.id}" />
            </span>
          </label>
        </li>
      `);

      this.el.find('ul').append(template);

    }

    return done();

  }

  commit() {

    return new Promise((resolve, reject) => {

      let data = this.selected;

      $.ajax({
        url: `/analysis/${this.service.client.id}/control/screenshots/`,
        type: 'POST',
        dataType: 'json',
        contentType: "application/json; charset=utf-8",
        data: JSON.stringify(data),
        success: (response, xhr) => {
          resolve();
        },
        error: err => {
          reject(err);
        }
      });

    });
  }

}

export { RDPSnapshotService, RDPSnapshotSelector };
