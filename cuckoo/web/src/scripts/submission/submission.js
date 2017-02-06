import * as InterfaceControllers from './components/InterfaceControllers';
import * as FileTree from './components/FileTree';
import * as Analysis from './components/Analysis';

const default_analysis_options = {
	'machine': 'default',
	'network-routing': 'internet',
	'options': {
		'enable-services': true,
		'enforce-timeout': false,
		'full-memory-dump': false,
		'no-injection': true,
		'process-memory-dump': true,
		'simulated-human-interaction': true
	},
	'package': 'python',
	'priority': 1,
	'timeout': 2,
	'vpn': 'united-states'
}

// appends a helper to handlebars for humanizing sizes
Handlebars.registerHelper('file_size', function(text) {
	return new Handlebars.SafeString(FileTree.humanizeBytes(parseInt(text)));
});

$(function() {

	var debugging = false;

	// if(debugging) {
	// 	$('.flex-grid__footer').css('display', 'none');
	// }

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
					serialize: function(response) {

						FileTree.FileTree.iterateFileStructure(response.data.files, function(item) {
							item.per_file_options = $.extend(new Object(), default_analysis_options);
							item.changed_properties = new Array();

							var parentContainer = FileTree.FileTree.getParentContainerName(item);
							if(parentContainer) item.arcname = parentContainer.filename;

						});

						analysis_ui.originalData = response.data;

						return response.data.files;

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

						$(info).on('click', function(e) {
							e.stopImmediatePropagation();
							controller.detailView(self);
						});

						return el;
					},

					folder: function(el, controller) {

						var _$d = $(el).find('div');
						var size = FileTree.Label('size', FileTree.humanizeBytes(FileTree.folderSize(this))); 

						if(this.type === 'container') {
							_$d.addClass('archive-container');
						}

						_$d.append(size);

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
										default: item.per_file_options['network-routing'],
										options: [
											{ name:'none', value:'none' },
											{ name:'drop', value:'drop' },
											{ name:'internet', value:'internet' },
											{ name:'inetsim', value:'inetsim' },
											{ name:'tor', value:'tor' }
										],
										extra_select: {
											title: 'VPN via',
											name: 'vpn-' + item.filetree.index,
											default: item.per_file_options['vpn'] || undefined,
											options: [
												{ name: 'France', value: 'france' },
												{ name: 'Russia', value: 'russia' },
												{ name: 'United States', value: 'united-states' },
												{ name: 'China', value: 'china' }
											]
										}
									}).on('change', function(value) {
										item.per_file_options['network-routing'] = value;
										setFieldValue.call(this, value);
									});

									var pkg = new this.SimpleSelect({
										name: 'package-' + item.filetree.index,
										title: 'Package',
										default: item.per_file_options['package'],
										options: [
											{ name: 'Python', value: 'python' },
											{ name: 'Javascript', value: 'js' }
										]
									}).on('change', function(value) {
										item.per_file_options['package'] = value;
										setFieldValue.call(this, value);
									});

									var priority = new this.TopSelect({
										name: 'piority-' + item.filetree.index,
										title: 'Priority',
										default: parseInt(item.per_file_options['priority']),
										options: [
											{ name: 'low', value: 0, className: 'priority-s' },
											{ name: 'medium', value: 1, className: 'priority-m' },
											{ name: 'high', value: 2, className: 'priority-l' }
										]
									}).on('change', function(value) {
										item.per_file_options['priority'] = value;
										setFieldValue.call(this, parseInt(value));
									});

									var config = new this.ToggleList({
										name: 'options-' + item.filetree.index,
										title: 'Options',
										extraOptions: true,
										default: item.per_file_options['options'],
										options: [
											{
												name: 'no-injection',
												label: 'No Injection',
												description: 'Disable behavioral analysis.'
											},
											{
												name: 'process-memory-dump',
												label: 'Process Memory Dump'
											},
											{
												name: 'full-memory-dump',
												label: 'Full Memory Dump',
												description: 'If the “memory” processing module is enabled, will launch a Volatality Analysis.'
											},
											{
												name: 'enforce-timeout',
												label: 'Enforce Timeout'
											},
											{
												name: 'simulated-human-interaction',
												label: 'Enable Simulated Human Interaction'
											},
											{
												name: 'enable-services',
												label: 'Enable Services',
												description: 'Enable simulated environment specified in the auxiliary configuration.'
											}
										],
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
										options: [
											{ name: 'default', value: 'default' },
											{ name: 'Cuckoo1', value: 'Cuckoo1' },
											{ name: 'Cuckoo2', value: 'Cuckoo2' }
										]
									}).on('change', function(value) {
										item.per_file_options['machine'] = value;
										setFieldValue.call(this, value);
									});

									form.add([network, [pkg, priority], config, machine]);
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
						default: default_analysis_options['network-routing'],
						options: [
							{ name:'none', value:'none' },
							{ name:'drop', value:'drop' },
							{ name:'internet', value:'internet' },
							{ name:'inetsim', value:'inetsim' },
							{ name:'tor', value:'tor' }
						],
						extra_select: {
							title: 'VPN via',
							name: 'vpn',
							on: {
								change: function() {
									// console.log('vpn changed');
								}
							},
							options: [
								{ name: 'France', value: 'france' },
								{ name: 'Russia', value: 'russia' },
								{ name: 'United States', value: 'united-states' },
								{ name: 'China', value: 'china' }
							]
						}
					});

					var pkg = new this.SimpleSelect({
						name: 'package',
						title: 'Package',
						default: default_analysis_options['package'],
						options: [
							{ name: 'Python', value: 'python' },
							{ name: 'Javascript', value: 'js' }
						]
					});

					var priority = new this.TopSelect({
						name: 'priority',
						title: 'Priority',
						default: default_analysis_options['priority'],
						options: [
							{ name: 'low', value: 0, className: 'priority-s' },
							{ name: 'medium', value: 1, className: 'priority-m' },
							{ name: 'high', value: 2, className: 'priority-l' }
						]
					});

					var config = new this.ToggleList({
						name: 'options',
						title: 'Options',
						default: default_analysis_options['options'],
						extraOptions: true,
						options: [
							{
								name: 'no-injection',
								label: 'No Injection',
								description: 'Disable behavioral analysis.'
							},
							{
								name: 'process-memory-dump',
								label: 'Process Memory Dump'
							},
							{
								name: 'full-memory-dump',
								label: 'Full Memory Dump',
								description: 'If the “memory” processing module is enabled, will launch a Volatality Analysis.'
							},
							{
								name: 'enforce-timeout',
								label: 'Enforce Timeout'
							},
							{
								name: 'simulated-human-interaction',
								label: 'Enable Simulated Human Interaction',
								selected: true
							},
							{
								name: 'enable-services',
								label: 'Enable Services',
								description: 'Enable simulated environment specified in the auxiliary configuration.'
							}
						]
					});

					var machine = new this.SimpleSelect({
						name: 'machine',
						title: 'Machine',
						default: default_analysis_options['machine'],
						options: [
							{ name: 'default', value: 'default' },
							{ name: 'Cuckoo1', value: 'Cuckoo1' },
							{ name: 'Cuckoo2', value: 'Cuckoo2' }
						]
					});

					var timeout = new this.TopSelect({
						name: 'timeout',
						title: 'Timeout',
						default: default_analysis_options['timeout'],
						units: 'minutes',
						options: [
							{ name: '1m', value: 0 },
							{ name: '2m', value: 1 },
							{ name: '5m', value: 2 },
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

							for(var val in values) {
								if(item.changed_properties && item.changed_properties.indexOf(val) == -1) {
									item.per_file_options[val] = values[val];
								}
							}
						}

						analysis_ui.filetree.each(function(item) {
							compareAndOverwrite(item);
						});

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

			var json = analysis_ui.getData({
				submit_id: window.submit_id
			}, false);

			console.log(json);
			return;
				
			$.ajax({
				url: '/submit/api/submit',
				type: 'POST',
				dataType: 'json',
				contentType: "application/json; charset=utf-8",
				data: json,
				success: function(data) {
					if(data.status === true){
	                    CuckooWeb.redirect("/submit/post/?id=" + data.data.join("&id="));
	                } else {
	                    alert("Submission failed: " + data.message);
	                }
				},
				error: function() {
					console.log(arguments);
					alert('submission failed! see the console for details.');
				}
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

});