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

export default class RDPSnapshotService extends Hookable {
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
