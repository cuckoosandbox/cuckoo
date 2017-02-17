class SubmissionTaskTable {

	constructor(options) {

		let self      = this;

		this.el       = options.el;
		this.task_ids = options.task_ids;
		this.interval = null;
		this.refreshRate = 1000; // ms

		// debug
		this.stopIntervalling = 10;
		this.curInterval = 0;

		if(this.task_ids.length) {
			this.interval = setInterval(function() {
				self._status(self._data);
				self.curInterval += 1;

				// debug
				if(self.curInterval == self.stopIntervalling) {
					self._clear();
				}
			}, this.refreshRate);
		}
	}

	_status(callback) {
		$.post('/analysis/api/tasks/info', JSON.stringify({ task_ids: this.task_ids }), callback);
	}

	_data(data) {
		console.log(data);
	}

	_clear() {
		if(this.interval) {
			clearInterval(this.interval);
		}
	}

}

export { SubmissionTaskTable };