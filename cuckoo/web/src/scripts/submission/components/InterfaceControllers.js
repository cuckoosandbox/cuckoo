// TEMPLATES
const TEMPLATES = {
	TopSelect: HANDLEBARS_TEMPLATES['control-top-select'],
	SimpleSelect: HANDLEBARS_TEMPLATES['control-simple-select'],
	ToggleList: HANDLEBARS_TEMPLATES['control-toggle-list']
}

// renders two interface controllers onto one row
class Split {
	constructor(elements) {
		this.elements = [];

		for(var el in elements) {
			this.add(elements[el]);
		}
	}
	add(element) {

		if(!element instanceof UserInputView) {
			console.error('Split only takes in UserInputControllers');
			return;
		}

		element.view.split_view = this;
		this.elements.push(element);
	}

	draw() {

		var el = document.createElement('div');
		el.classList.add('fieldset__split');

		for(var element in this.elements) {
			var html = this.elements[element].view.render();
			el.appendChild(html);
		}
		return el;
	}

	// this is NOT an event handling function.
	// this method persists an event callback to its elements
	on(event, fn) {
		if(!event || typeof event !== 'string') return;
		if(!fn && typeof fn !== 'function') return;
		this.elements.forEach(function(element) {
			element.on(event, fn);
		});
	}

}

// USERINPUTVIEW
class UserInputView {

	constructor(controller) {
		this.controller = controller;
		this.template = null;
		this.html = null;
		this.model = null;
		this.split_view = null;
		this.callbacks = {};
	}

	createWrapper() {
		var wrap = document.createElement('fieldset');
		wrap.classList.add('flex-form__module');
		wrap.setAttribute('id', this.controller.name);
		return wrap;
	}

	setupModel(model) {

		if(!this.model) {
			this.model = model;	
		}  else {
			for(var prop in model) {
				this.model[prop] = model[prop];
			}
		}
	}

	render() {
		var html = this.template(this.model);
		var wrap = this.createWrapper();
		wrap.innerHTML = html;
		this.html = wrap;
		return wrap;
	}

	runCallbacks() {
		var self = this;
		for(var cb in this.callbacks) {
			if(this.callbacks instanceof Function) this.callbacks[cb].call(this.html, this.controller);
			if(this.callbacks instanceof Array) {
				this.callbacks[cb].forEach(function(callback) {
					if(typeof callback === 'function') callback.call(self.html, self.controller);
				});
			}
		}
	}

	afterRender(cb) {
		if(!cb) return;
		this.callbacks.afterRender = cb;
	}

}

// USERINPUTCONTROLLER
class UserInputController {

	constructor(config) {

		if(!config) config = {};

		this.config = config;
		this.view = new UserInputView(this);
		this.name = config.name || '';
		this.title = config.title || '';
		this.value = config.value || '';
		this.type = config.type || '';
		this.form = config.form || '';
		this.default = config.default || '';
		this.units = config.units || '';

		this.events = {
			change: [],
			render: [],
			init: []
		}

		if(config.on) {
			for(var prop in config.on) {
				this.on(prop, config.on[prop]);
			}
		}

		// assign default value to value if defined
		if(this.default.length) {
			this.value = this.default;
		}

		this.view.setupModel({
			name: this.name,
			title: this.title,
			controller: this
		});

	}

	setValue(val, cb) {
		this.value = val;
		this.trigger('change', this.value);
		if(cb) cb();
	}

	getValue() {
		return this.value;
	}

	on(event, fn) {

		if(!this.events.hasOwnProperty(event) || !fn) return;
		this.events[event].push(fn);

		return this;
	}

	trigger(event, data) {
		let self = this;
		if(!this.events.hasOwnProperty(event)) return;	
		this.events[event].forEach(function(fn) {
			fn.call(self, data);
		});	

		return this;
	}

}

// SIMPLESELECT CONSTRUCTOR (EXTENDS USERINPUTCONTROLLER)
class SimpleSelect extends UserInputController {

	constructor(config) {
		super(config);
		this.options = config.options;

		this.initialise();
	}

	initialise() {

		var self = this;
		this.view.template = TEMPLATES.SimpleSelect;

		this.view.setupModel({
			options: this.options,
			doc_link: this.config.doc_link
		});

		if(this.default) {
			this.options.forEach(function(opt) {
				if(opt.value == self.default) {
					opt.selected = true;
					self.setValue(self.default);
				}
			});
		}

		this.view.afterRender(function(controller) {
			$(this).find('select').bind('change', function() {
				controller.setValue(this.value);
			});
		});

	}

}

// TOPSELECT CONSTRUCTOR (EXTENDS USERINPUTCONTROLLER)
class TopSelect extends UserInputController {

	constructor(config) {
		if(!config) config = {};
		super(config);

		this.options = this.config.options;
		this.extra_select = this.config.extra_select;
		this.units = this.config.units;

		this.initialise();
	}

	initialise() {

		let self = this;
		let extra = this.extra_select;
		let totalItems = this.options.length;
		let top_items = [];
		let rest_items = [];

		var snapped = false;

		if(totalItems >= 5) {
			top_items = this.options.slice(0,5);
			rest_items = this.options.slice(5, totalItems);
		} else {
			top_items = this.options;
		}

		if(this.default) {

			this.options.forEach(function(opt) {

				if(opt.value == self.default) {
					opt.selected = true;
					self.setValue(self.default);
					snapped = true;
				}

			});

			if(!snapped) {
				self.setValue(self.default);
				$(self.view.html).find('.manual-input > input').val(self.getValue());
			}

		}

		// controller configures the view
		this.view.template = TEMPLATES.TopSelect;

		// implement a new method on the view which will deselect radio's
		this.view.deselectRadios = function() {
			$(this.html).find('input:radio').prop('checked', false);
		}

		this.view.unsetCustom = function() {
			$(this.html).find('.manual-input').removeClass('active');
			$(this.html).find('.manual-input > input').val('');
		}

		// implement a new method on the view which will reset the selectbox
		this.view.resetOtherSelect = function() {
			$(this.html).find('select[name="'+this.controller.name+'-other"] option:first-child').prop('selected', true);
		}

		this.view.resetAlternateSelect = function() {
			if(!extra) return;
			$(this.html).find('select#' + extra.name + ' option:first-child').prop('selected', true);
		}

		// create model on view
		this.view.setupModel({
			top_items: top_items,
			rest_items: rest_items,
			extra_select: this.config.extra_select,
			doc_link: this.config.doc_link,
			snapped: snapped
		});

		// hook up interaction things
		this.view.afterRender(function(controller) {

			// this = html	
			// controller = interface base controller

			$(this).find('input:radio').bind('change', function(e) {
				controller.setValue(this.value);
				self.view.resetOtherSelect();
				self.view.resetAlternateSelect();
				self.view.unsetCustom();
			});

			$(this).find('select[name="'+controller.name+'-other"]').bind('change', function(e) {
				controller.setValue(this.value);
				self.view.deselectRadios();
				self.view.resetAlternateSelect();
				self.view.unsetCustom();
			});

			$(this).find('.manual-input > input').bind('keyup', function(e) {
				controller.setValue(this.value);
				$(this).parent().addClass('active');
				self.view.deselectRadios();
				self.view.resetAlternateSelect();
			});

			if(!snapped) {
				$(this).find('.manual-input').addClass('active');
				$(this).find('.manual-input > input').val(self.value);
			}

			// to make the extra input a SEPERATE function,
			// we create a new input controller - without the view -
			// we already have the view. we just need the controller.
			if(extra) {

				var inp = new UserInputController({
					name: extra.name,
					title: extra.title,
					on: extra.on || {}
				});

				if(extra.default) {

					extra.options.forEach(function(opt) {
						if(opt.value == extra.default) {
							opt.selected = true;
							inp.setValue(extra.default);
						}
					});

				}

				if(controller.form) controller.form.add(inp);

				$(controller.view.html).find('select#' + extra.name).bind('change', function(e) {
					inp.setValue($(this).val());
					self.view.deselectRadios();
					self.view.resetOtherSelect();
				});

			}

		});

	}

	getValue() {
		return this.value;
	}

}

// TOGGLE LIST with support for EXTRA USER INPUT
class ToggleList extends UserInputController {

	constructor(config) {
		super(config);

		this.initialised = false;
		this.options = config.options;
		this.config = config;
		this.value = {};
		this.custom_options = config.custom_options || {};
		this.options_extra_predefined = config.options_extra_predefined || [];

		this.events = $.extend(this.events, {
			remove: []
		});

		if(this.default) {
			var self = this;

			this.options = this.options.map(function(option) {
				option.selected = false;
				if(self.default[option.name] === true) {
					option.selected = true;
				}
				return option;
			});

		}

		this.initialise();
	}

	initialise() {

		var self = this;
		this.view.template = TEMPLATES.ToggleList;

		this.view.setupModel({
			options: this.options,
			extraOptions: this.config.extraOptions,
			doc_link: this.config.doc_link
		});

		for(var opt in this.options) {
			this.value[this.options[opt].name] = this.options[opt].selected || false;
		}

		this.trigger('init');

		this.view.afterRender(function() {

			$(this).find('input:checkbox').bind('change', function(e) {
				self.onToggleChange.call(this, e, self);
			}).each(function() {
				self.onToggleChange.call(this, null, self);
			});

			if(self.config.extraOptions) {
				self.initialiseExtraOptions();	
			}

			self.initialised = true;

		});

		return this;

	}

	setOption(name, val) {
		this.value[name] = val;

		if(this.initialised) {
			this.trigger('change', this.getValue());	
		}
	}

	onToggleChange(e, self) {
		var $checkbox = $(this);
		var optName = $checkbox.data('option');
		self.setOption(optName, $checkbox.is(':checked'));
	}

	initialiseExtraOptions() {

		var self = this;

		let $newOptionName = $(this.view.html).find('table tfoot input[name=new-key]');
		let $newOptionValue = $(this.view.html).find('table tfoot input[name=new-value]');

		$(this.view.html).find('table tfoot input[name=new-key], table tfoot input[name=new-value]').bind('keydown', function(e) {

			var optName = $newOptionName.val();
			var optValue = $newOptionValue.val();

			switch(e.keyCode) {
				case 13:
					self.commit(optName, optValue);
				break;
			}

		});

		if(this.options_extra_predefined.length) {
			this.options_extra_predefined.forEach(function(item) {
				self.commit(item.key, item.value);
			});
		}

	}

	removeTableRow(key) {
		$(this.view.html).find('tr[data-option="'+key+'"]').remove();
	}

	createTableRow(key, value) {

		var $row = document.createElement('tr');
		var $key = document.createElement('td');
		var $val = document.createElement('td');
		var $remove = document.createElement('a');
		var $icon = document.createElement('i');

		$remove.classList.add('remove');
		$icon.classList.add('fa');
		$icon.classList.add('fa-remove');

		$remove.appendChild($icon);

		$key.innerHTML = key;
		$val.innerHTML = value;
		$val.appendChild($remove);
		$row.appendChild($key);
		$row.appendChild($val);

		$key.classList.add('key');
		$val.classList.add('value');

		$row.setAttribute('data-option', key);

		return $row;
	}

	commit(key, value) {

		const self = this;

		let $newOptionName = $(this.view.html).find('table tfoot input[name=new-key]');
		let $newOptionValue = $(this.view.html).find('table tfoot input[name=new-value]');

		if(this.custom_options.hasOwnProperty(key)) return false;
		if(!key || !value) return false;

		this.custom_options[key] = value;

		var el = this.createTableRow(key, value);
		$(this.view.html).find('table tbody').append(el);

		$(el).find('.remove').bind('click', function(e) {
			e.preventDefault();
			self.remove($(this).parents('tr').data('option'));
			self.trigger('remove', self.getValue());
		});

		// resets and focusses back the input fields
		$newOptionName.val('');
		$newOptionValue.val('');
		$newOptionName.focus();

		this.trigger('change', this.getValue());
	}

	remove(key) {
		if(this.custom_options.hasOwnProperty(key)) {
			delete this.custom_options[key];
			this.removeTableRow(key);
		}
	}

	getValue() {

		var list = {};

		for(var opt in this.value) {
			list[opt] = this.value[opt];
		}

		if(this.config.extraOptions) {
			for(var o in this.custom_options) {
				list[o] = this.custom_options[o];
			}
		}

		return list;

	}

}

// FORM CONSTRUCTOR
class Form {

	constructor(config) {

		this.config = config;
		this.fields = {};
		this.container = this.config.container || null;

		this.events = {
			change: [],
			render: []
		}

		this.config.configure.call({
			TopSelect: TopSelect,
			SimpleSelect: SimpleSelect,
			Split: Split,
			ToggleList: ToggleList
		}, this);

	}

	on(event, fn) {
		if(!this.events.hasOwnProperty(event) || !fn) return;
		this.events[event].push(fn);
		return this;
	}

	trigger(event, data) {

		let self = this;

		if(!this.events.hasOwnProperty(event)) return;	
		this.events[event].forEach(function(fn) {
			fn.call(self, data);
		});	

		return this;
	}

	add(element) {

		let self = this;

		if(element instanceof Array) {
			element.forEach(function(item) {
				if(item instanceof Array) {
					var s = new Split(item);
					self.add(s);
				} else {
					self.add(item);
				}
			});
		} else {
			if(element instanceof UserInputController || element instanceof Split) {
				this.fields[element.name] = element;	
				this.fields[element.name].form = this;

				// this hooks a callback listener to a change event 
				// from an included field. if it triggers, it will trigger
				// the form 'change' event. 
				element.on('change', function() {
					self.trigger('change', self.serialize());
				});

			} else {
				console.error('Only elements from instance UserInputController and Split are allowed!');
			}
		}

	}

	draw() {

		for(var f in this.fields) {
			var field = this.fields[f];

			if(field instanceof UserInputController) {

				field.view.html = field.view.render();
				this.container.appendChild(field.view.html);
				if(field.view.callbacks.afterRender) field.view.callbacks.afterRender.call(field.view.html, field);

			} else if (field instanceof Split) {
				this.container.appendChild(field.draw());

				for(var el in field.elements) {
					var f = field.elements[el];
					if(f.view.callbacks.afterRender) {
						f.view.callbacks.afterRender.call(f.view.html, f);
					}
				}

			}
		}

	}

	serialize() {
		var ret = {};

		function setValue(key, value) {
			ret[key] = value;
		}

		for(var f in this.fields) {
			var field = this.fields[f];
			if(typeof field.getValue === 'function') {
				setValue(field.name, field.getValue());
			}
			if(field instanceof Split) {
				field.elements.forEach(function(el) {
					if(typeof el.getValue === 'function') setValue(el.name, el.getValue());
				});
			}
		}
		
		return ret;
	}

}

export { SimpleSelect, TopSelect, Split, ToggleList, Form }