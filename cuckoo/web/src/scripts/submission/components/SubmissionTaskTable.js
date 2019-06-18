class SubmissionTaskTable {

	constructor(options) {

		var self             = this;

		this.el              = options.el;
		this.task_ids        = options.task_ids;
		this.interval        = null;
		this.refreshRate     = options.refreshRate ? options.refreshRate : 1000; // ms
		this.debug 		     = options.debug;
		this.request_pending = false;
		this.onRender 		 = options.onRender ? options.onRender : function() {};

		// debug
		this.stopIntervalling = 1;
		this.curInterval = 0;

		if(this.task_ids.length) {
			this.interval = setInterval(function() {
				self._status();
				self.curInterval += 1;

				// debug
				if(self.debug && (self.curInterval == self.stopIntervalling)) {
					self._clear();
				}
			}, this.refreshRate);

			self._status();
		}
	}

	// does a status check
	_status(callback) {

		var self = this;

		// this blocks out making requests if we are already doing a request.
		// this makes every request 'wait' untill all requests did finish.
		if(this.request_pending) return;
		this.request_pending = true;

		this.setStatusText('Getting status...');

		CuckooWeb.api_post('/analysis/api/tasks/info/', {
			"task_ids": self.task_ids
		}, function(response) {
			self._data(response);
			self.request_pending = false;
		}, function(err) {
			self._clear();
			self.setStatusText('There was an error!');
		});
	}

	// processes the data
	_data(response) {

		this.setStatusText('Done');

		var data = response.data;

		// building the check, but it's always an object,
		// so do some array formatting here, while keeping
		// the correct order.
		if(!(data instanceof Array)) {
			var arr = [];
			for(var d in response.data) {
				arr.push(response.data[d]);
			}
			data = arr.sort(function(a, b) {
				return a.id > b.id;
			});
		}

		// humanize the date formats, or any other kind of data
		data = data.map(function(item) {
			item.date_added = moment(item.added_on).format('DD/MM/YYYY');
			item.time_added = moment(item.added_on).format('HH:mm');
			item.is_ready   = (item.status == 'reported');
			item.is_running = (item.status == 'running');
			item.remote_control = item.options.hasOwnProperty('remotecontrol');
			item.show_rc_toggle = (item.remote_control && item.is_running);
			return item;
		});

		this._draw(data);
	}

	// draws the table content from Handlebars into the table
	_draw(data) {
		var template = HANDLEBARS_TEMPLATES['submission-task-table-body'];
		$(this.el).find('tbody').html(template({ tasks: data }));
		this.onRender($(this.el));
	}

	// clears the interval
	_clear() {
		if(this.interval) clearInterval(this.interval);
		this.request_pending = false;
	}

	setStatusText(text) {
		$(this.el).find('tfoot .ajax-status').text(text);
	}

}

export { SubmissionTaskTable };
