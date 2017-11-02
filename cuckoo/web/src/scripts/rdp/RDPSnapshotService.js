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
    let template = `
      <li data-snapshot-id="${s.id}">
        <figure><img src="/static/graphic/screenshot-sample.png" alt="snapshot" /></figure>
        <div class="rdp-snapshots--controls">
          <a href="#"><i class="fa fa-remove"></i></a>
        </div>
      </li>
    `;

    // append this to the list
    this.$.prepend(template);
  }

}

class Snapshot {
  constructor(id) {
    this.id = 0;
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
    this.count++;
    this.bar.add(s);
    this.dispatchHook('create', s);
  }

  remove() {
    this.dispatchHook('remove', {});
  }

  total() {
    return this.snapshots.length;
  }

}
