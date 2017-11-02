import Hookable from './Hookable';

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
    this.dispatchHook('create', s);
  }

  remove() {
    this.dispatchHook('remove', {});
  }

  total() {
    return this.snapshots.length;
  }

}
