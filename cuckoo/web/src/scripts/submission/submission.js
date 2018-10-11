import * as InterfaceControllers from './components/InterfaceControllers';
import * as FileTree from './components/FileTree';
import * as Analysis from './components/Analysis';
import { SubmissionTaskTable } from './components/SubmissionTaskTable';

// default values for the analysis options
var default_analysis_options = {
	'machine': 'default',
	'network-routing': 'internet',
	'options': {
		'enforce-timeout': false,
		'full-memory-dump': false,
		'enable-injection': true,
		'process-memory-dump': true,
		'simulated-human-interaction': true,
		'remote-control': false
	},
	'package': null,
	'priority': 1,
	'timeout': 120,
	'vpn': 'united-states',
	'available_vpns': [],
	'available_machines': []
}

// default option set for the submission form
var submission_options = [
	{
		name: 'remote-control',
		label: 'Remote Control',
		description: 'Enables Guacamole UI for VM'
	},
	{
		name: 'enable-injection',
		label: 'Enable Injection',
		description: 'Enable behavioral analysis.'
	},
	{
		name: 'process-memory-dump',
		label: 'Process Memory Dump'
	},
	{
		name: 'full-memory-dump',
		label: 'Full Memory Dump',
		description: 'If Volatility has been enabled, process an entire VM memory dump with it.'
	},
	{
		name: 'enforce-timeout',
		label: 'Enforce Timeout'
	},
	{
		name: 'simulated-human-interaction',
		label: 'Enable Simulated Human Interaction',
		selected: true,
		description: 'disable this feature for a better experience when using Remote Control',
		showWhen: {
			'remote-control': true
		}
	}
];

// package field contents - hardcoded options vs auto-detected properties
// gets updated when packages come back that aren;t in this array in the response
// serialization code.
var default_package_selection_options = [
    'default', 'com', 'cpl', 'dll', 'doc', 'exe', 'generic',
    'ie', 'ff', 'jar', 'js', 'jse', 'hta', 'hwp', 'msi', 'pdf',
    'ppt', 'ps1', 'pub', 'python', 'vbs', 'wsf', 'xls', 'zip'
];
var routing_prefs = {};

// appends a helper to handlebars for humanizing sizes
Handlebars.registerHelper('file_size', function(text) {
	return new Handlebars.SafeString(FileTree.humanizeBytes(parseInt(text)));
});

$(function() {

	var debugging = (window.location.toString().indexOf('#debugging') !== -1);

	if(debugging) {
		console.debug('You run this module in debug mode. to disable it, remove #debugging from the url.');
		console.debug('Clicking analyze will output the JSON results to the console.')
		console.debug('Submitting is unavailable in this mode.');
		$('.flex-grid__footer').css('display', 'none');
	}

	if(document.getElementById('analysis-configuration') !== null) {

		// collects the entire ui of this page
		var analysis_ui = new Analysis.AnalysisInterface({
			container: document.getElementById('analysis-configuration'),
			// specifies the file tree configuration
			filetree: {
				config: {
					label: 'filetree',
					autoExpand: true,
					sidebar: document.getElementById('filetree-detail'),
					nameKey: 'filename', // name of the file name property
					isDirectory: function(item) {
						return item.type === 'directory' || item.type === 'container';
					}
				},
				load: {
					url: '/submit/api/filetree',
					method: 'POST',
					params: {
						"submit_id": window.submit_id
					},
					error: function(err) {

						let $ftErr = $(`<div class="filetree-error">
							<div class="cross">
								<span class="cross-line"></span>
								<span class="cross-line"></span>
							</div>
							<p class="error-message">Something went wrong.</p>
						</div>`);

						$(this.el).html($ftErr);
						setTimeout(() => {
							$ftErr.addClass('in');
						}, 500);

						// $(this.el).html(`<div class="filetree-error">
						// 	<div class="cross">
						// 		<span class="cross-line"></span>
						// 		<span class="cross-line"></span>
						// 	</div>
						// 	<p class="error-message">Something went wrong.</p>
						// </div>`);
					},
					serialize: function(response) {

						// set up defaults for form and settings
						if(response.defaults) {
							default_analysis_options = response.defaults;

							// extract the routing settings and delete
							routing_prefs = default_analysis_options.routing;
							default_analysis_options.routing = routing_prefs.route;

							// format the vpns array to work for the form field, using a 'name-value']
							default_analysis_options.available_vpns = routing_prefs.vpns.map(function(vpn) {
								return {
									name: vpn,
									value: vpn
								}
							});

							// if we have 'null' for machines, force it to be mappable by replacing
							// it with an empty array instead.
							if(!default_analysis_options.machine) {
								default_analysis_options.machine = new Array();
							}

							// parse the available machines
							default_analysis_options.available_machines = default_analysis_options.machine.map(function(machine) {
								return {
									name: machine,
									value: machine
								}
							});

							// create a 'default=null' value
							default_analysis_options.available_machines.unshift({
								name: 'default',
								value: null
							});

							// set the value to 'default' (or null in this case)
							default_analysis_options.machine = default_analysis_options.available_machines[0].value;

						}

						analysis_ui.originalData = response.files;

						FileTree.FileTree.iterateFileStructure(response.files, function(item) {

							item.per_file_options = $.extend(new Object(), default_analysis_options);
							item.changed_properties = [];

							// machine guess: package options
							// - also preselects the package field if available

							if(item.package) {
								item.per_file_options['package'] = item.package
								if(default_package_selection_options.indexOf(item.package) == -1) {
									default_package_selection_options.push(item.package);
								}
								item.changed_properties.push('package');
							}

							var parentContainer = FileTree.FileTree.getParentContainerName(item);
							if(parentContainer) item.arcname = parentContainer.filename;

						});

						default_package_selection_options = default_package_selection_options.map(function(opt) {
							return {
								name: opt,
								value: opt
							};
						});

						return response.files;

					}
				},
				transform: {
					file: function(el, controller) {

						var self = this;

						// this = item
						var _$d = $(el).find('div');
						var size = FileTree.Label('size', FileTree.humanizeBytes(this.size));
						var info = FileTree.Label('info', '<i class="fa fa-info-circle"></i>', 'a');

						// adds the meta data
						_$d.append(info, size);

						if(this.duplicate) {
							var duplicate = FileTree.Label('duplicate', 'duplicate file');
							_$d.append(duplicate);
						}

						$(info).on('click', function(e) {
							e.stopImmediatePropagation();
							controller.detailView(self);
						});

						// make sure the filename is escaped to prevent XSS attacks
						this.filename = CuckooWeb.escapeHTML(this.filename);

						return el;
					},

					folder: function(el, controller) {

						var self = this;
						var _$d = $(el).find('div');
						var size = FileTree.Label('size', FileTree.humanizeBytes(FileTree.folderSize(this)));
						var archive, info;

						if(this.type === 'container') {
							_$d.addClass('archive-container');
						}

						_$d.append(size);

						if(!this.preview) {
							// _$d.find('strong').addClass('skip-auto-expand');
							_$d.parent().addClass('skip-auto-expand');
							archive = FileTree.Label('archive', 'Archive');

							if(this.type !== 'directory') {
								info = FileTree.Label('info', '<i class="fa fa-info-circle"></i>', 'a');
								_$d.prepend(info);

								// makes info circle clickable
								$(info).on('click', function(e) {
									e.stopImmediatePropagation();
									controller.detailView(self);
								});
							}
							_$d.append(archive);

						}

						return el;
					}
				},
				after: {
					selectionView: function() {},
					detailView: function(el, filetree) {

						var item = this;
						var $per_file_options = $(el).find('.per-file-options')[0];

						if($per_file_options) {

							// sets a value on a field
							function setFieldValue(value) {

								var field = fieldName(this.name);

								if(item.changed_properties.indexOf(field) == -1) {
									item.changed_properties.push(field);
								}

								item.per_file_options[field] = value;
							}

							// returns the fieldname as is
							function fieldName(str) {
								var spl = str.split('-');
								spl.splice(-1, 1);
								return spl.join('-');
							}

							var form = new InterfaceControllers.Form({
								container: $per_file_options,
								configure: function(form) {

									var network = new this.TopSelect({
										name: 'network-routing-' + item.filetree.index,
										title: 'Network Routing',
										doc_link: 'https://cuckoo.sh/docs/installation/host/routing.html',
										default: item.per_file_options['network-routing'],
										options: [
											{ name:'none', value:'none', disabled: (routing_prefs['none'] === false) },
											{ name:'drop', value:'drop', disabled: (routing_prefs['drop'] === false) },
											{ name:'internet', value:'internet', disabled: (routing_prefs['internet'] === false) },
											{ name:'inetsim', value:'inetsim', disabled: (routing_prefs['inetsim'] === false) },
											{ name:'tor', value:'tor', disabled: (routing_prefs['tor'] === false) }
										],
										extra_select: {
											title: 'VPN via',
											name: 'vpn-' + item.filetree.index,
											default: item.per_file_options['vpn'] || undefined,
											disabled: (routing_prefs['vpn'] === false || default_analysis_options.available_vpns.length === 0),
											options: default_analysis_options.available_vpns
										}
									}).on('change', function(value) {
										item.per_file_options['network-routing'] = value;
										setFieldValue.call(this, value);
									});

									var pkg = new this.SimpleSelect({
										name: 'package-' + item.filetree.index,
										title: 'Package',
										doc_link: 'https://cuckoo.sh/docs/usage/packages.html',
										default: item.per_file_options['package'],
										options: default_package_selection_options
									}).on('change', function(value) {

										item.per_file_options['package'] = value;
										if(value == 'default') value = null;
										setFieldValue.call(this, value);

									});

									var priority = new this.TopSelect({
										name: 'piority-' + item.filetree.index,
										title: 'Priority',
										default: parseInt(item.per_file_options['priority']),
										options: [
											{ name: 'low', value: 1, className: 'priority-s' },
											{ name: 'medium', value: 2, className: 'priority-m' },
											{ name: 'high', value: 3, className: 'priority-l' }
										]
									}).on('change', function(value) {
										item.per_file_options['priority'] = value;
										setFieldValue.call(this, parseInt(value));
									});

									var timeout = new this.TopSelect({
										name: 'timeout-' + item.filetree.index,
										title: 'Timeout',
										default: item.per_file_options['timeout'],
										units: 'seconds',
										options: [
											{ name: 'short', value: 60, description: '60' },
											{ name: 'medium', value: 120, description: '120' },
											{ name: 'long', value: 300, description: '300' },
											{ name: 'custom', manual: true }
										]
									}).on('change', function(value) {
										item.per_file_options['timeout'] = value;
										setFieldValue.call(this, value);
									});

									var config = new this.ToggleList({
										name: 'options-' + item.filetree.index,
										title: 'Options',
										extraOptions: true,
										default: item.per_file_options['options'],
										options: submission_options,
										on: {
											init: function() {

												/*
													attach any predefined values to the stack
												 */

												var custom = [];

												var default_options = this.options.map(function(item) {
													return item.name;
												});

												for(var default_option in this.default) {
													if(default_options.indexOf(default_option) == -1) {
														custom.push({
															key: default_option,
															value: this.default[default_option]
														});
													}
												}

												this.options_extra_predefined = custom;

											},
											change: function(value) {
												item.per_file_options['options'] = value;
												setFieldValue.call(this, value);
											}
										}
									});

									var machine = new this.SimpleSelect({
										name: 'machine-' + item.filetree.index,
										title: 'Machine',
										default: item.per_file_options['machine'],
										options: default_analysis_options.available_machines
									}).on('change', function(value) {
										item.per_file_options['machine'] = value;
										setFieldValue.call(this, value);
									});

									form.add([network, [pkg, priority], timeout, config, machine]);

									form.draw();

								}
							});

						}

					}
				}
			},

			// specifies the form configuration
			form: {
				container: document.getElementById('submission-config'),
				configure: function(form) {

					// this configuration allows for dynamic (yes, dynamic) forms

					var network = new this.TopSelect({
						name: 'network-routing',
						title: 'Network Routing',
						default: default_analysis_options['routing'],
						doc_link: 'https://cuckoo.sh/docs/installation/host/routing.html',
						options: [
							{ name:'none', value:'none', disabled: (routing_prefs['none'] === false) },
							{ name:'drop', value:'drop', disabled: (routing_prefs['drop'] === false) },
							{ name:'internet', value:'internet', disabled: (routing_prefs['internet'] === false) },
							{ name:'inetsim', value:'inetsim', disabled: (routing_prefs['inetsim'] === false) },
							{ name:'tor', value:'tor', disabled: (routing_prefs['tor'] === false) }
						],
						extra_select: {
							title: 'VPN via',
							name: 'vpn',
							disabled: (routing_prefs['vpn'] === false || default_analysis_options.available_vpns.length === 0),
							on: {
								change: function() {
									// console.log('vpn changed');
								}
							},
							options: default_analysis_options.available_vpns
						}
					});

					var pkg = new this.SimpleSelect({
						name: 'package',
						title: 'Package',
						doc_link: 'https://cuckoo.sh/docs/usage/packages.html',
						default: default_analysis_options['package'],
						options: default_package_selection_options
					}).on('change', function(value) {

						// sets all items to the correct value of package, this does
						// not seem to work correctly, so this basically forces the
						// correct value.
						analysis_ui.filetree.each(function(item) {
							item.per_file_options.package = value;
						});

					});

					var priority = new this.TopSelect({
						name: 'priority',
						title: 'Priority',
						default: default_analysis_options['priority'],
						options: [
							{ name: 'low', value: 1, className: 'priority-s' },
							{ name: 'medium', value: 2, className: 'priority-m' },
							{ name: 'high', value: 3, className: 'priority-l' }
						]
					});

					var config = new this.ToggleList({
						name: 'options',
						title: 'Options',
						default: default_analysis_options['options'],
						extraOptions: true,
						options: submission_options
					});

					var machine = new this.SimpleSelect({
						name: 'machine',
						title: 'Machine',
						default: default_analysis_options['machine'],
						options: default_analysis_options['available_machines']
					});

					var timeout = new this.TopSelect({
						name: 'timeout',
						title: 'Timeout',
						default: default_analysis_options['timeout'],
						units: 'seconds',
						options: [
							{ name: 'short', value: 60, description: '60' },
							{ name: 'medium', value: 120, description: '120' },
							{ name: 'long', value: 300, description: '300' },
							{ name: 'custom', manual: true }
						]
					});

					// an array inside this array will render the elements in a split view
					form.add([network, [pkg, priority], timeout, config, machine]);
					form.draw();

					// this gets fired EVERY time one of the fields
					// insdie the form gets updated. it sends
					// back an object with all the current values of
					// the form instance.
					form.on('change', function(values) {

						function compareAndOverwrite(item) {

							// makes only exception rule for 'package'
							for(var val in values) {
								if(item.changed_properties && item.changed_properties.indexOf(val) == -1 && val !== 'package') {
									item.per_file_options[val] = values[val];
								}
							}
						}

						analysis_ui.filetree.each(function(item) {
							compareAndOverwrite(item);
						});

						// update any active detail views, respecting custom presets made
						// by the user. Actually 're-render' the current detail view to persist
						// default settings 'asynchonously' - as you would expect.
						if(analysis_ui.filetree.detailViewActive) {
							var active_index = analysis_ui.filetree.activeIndex;
							analysis_ui.filetree.detailView(analysis_ui.filetree.getIndex(active_index));
						}

					});

				}
			},
			// base configuration for the dnd uploader
			dndupload: {
				endpoint: '/submit/api/presubmit',
				target: 'div#dndsubmit',
				template: HANDLEBARS_TEMPLATES['dndupload'],
				success: function(data, holder) {

					$(holder).removeClass('dropped');
					$(holder).addClass('done');

					// fake timeout
					setTimeout(function() {
						window.location.href = data.responseURL;
					}, 1000);

				},
				error: function(uploader, holder) {
					$(holder).addClass('error');
				},
				progress: function(value, holder) {
					// thisArg is bound to the uploader
					if(value > 50 && !$(holder).hasClass('progress-half')) {
						$(holder).addClass('progress-half');
					}

					$(this.options.target).find(".alternate-progress").css('transform', `translateY(${100-value}%)`);
				},
				dragstart: function(uploader, holder) {
					holder.classList.add('hover');
				},
				dragend: function(uploader, holder) {
					holder.classList.remove('hover');
				},
				drop: function(uploader, holder) {
					holder.classList.remove('hover');
					holder.classList.add('dropped');
				}
			}
		});

		$('#start-analysis').bind('click', function(e) {

			e.preventDefault();

			var data = JSON.parse(analysis_ui.getData({
				'submit_id': window.submit_id
			}, true));

			if(!data.file_selection.length) {
				alert('Please select some files first.');
				return;
			}

			// $(".page-freeze").addClass('in');
			CuckooWeb.toggle_page_freeze(true,"We're processing your submission... This could take a few seconds.");

			if(debugging) {
				console.log(data);
				return;
			}

			CuckooWeb.api_post('/submit/api/submit', data, function(data) {
				if(data.status === true){
					// redirect to submission success page
					window.location = `/submit/post/${data.submit_id}`;
				} else {
					// alert("Submission failed: " + data.message);
					CuckooWeb.error_page_freeze("Something went wrong! please try again.");
				}
			}, function() {
				console.log(arguments);
				// alert('submission failed! see the console for details.');
				CuckooWeb.error_page_freeze("Something went wrong! please try again.");
			});
		});

		$("#reset-options").bind('click', function(e) {
			e.preventDefault();
		});

		$(".upload-module .grouped-buttons a").on('shown.bs.tab', function(e) {
			$(e.target).parent().find('a').removeClass('active');
			$(this).addClass('active');
		});

		// taken from the previous submit functionality
		$("input#urlhash").click(function () {

            var urls = $("textarea#presubmit_urlhash").val();
            if (urls == "") {
                return;
            }

            CuckooWeb.api_post("/submit/api/presubmit", {
                "data": urls,
                "type": "strings"
            }, function (data) {
                CuckooWeb.redirect("/submit/pre/" + data.submit_id);
            }, function(data){
                console.log("err: " + data);
            });

        });

	}

	// submission task summary init
	if(document.getElementById('submission-task-table') !== null) {
		var taskTable = new SubmissionTaskTable({
			el: document.getElementById('submission-task-table'),
			task_ids: task_ids,
			debug: false, // set to true to do 10 calls max and stop
			refreshRate: 2500,
			onRender: function(el) {
				// opens up the task in a new task, if this task has finished processing
				el.find('tbody > tr.finished').bind('click', function() {
					var id = $(this).data('taskId');
					window.open(`/analysis/${id}`);
				});
			}
		});

	}

});
