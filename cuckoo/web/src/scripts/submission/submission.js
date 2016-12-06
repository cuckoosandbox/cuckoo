import * as FileTree from './components/FileTree';
import * as Analysis from './components/Analysis';

// appends a helper to handlebars for humanizing sizes
Handlebars.registerHelper('file_size', function(text) {
	return new Handlebars.SafeString(FileTree.humanizeBytes(parseInt(text)));
});

$(function() {

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
						return item.type === 'directory';
					}
				},
				load: {
					url: '/submit/api/filetree',
					method: 'POST',
					params: {
						"submit_id": window.submit_id
					},
					serialize: function(response) {
						console.log(response);
						return response.data.files[0];
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
						_$d.append(size);

						return el;
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
						options: [
							{ name:'none', value:'none' },
							{ name:'drop', value:'drop' },
							{ name:'internet', value:'internet', selected: true },
							{ name:'inetsim', value:'inetsim' },
							{ name:'tor', value:'tor' }
						],
						extra_select: {
							title: 'VPN via',
							name: 'vpn',
							options: [
								{ name: 'France', value: 'FR-fr' }
							]
						}
					});

					var pkg = new this.SimpleSelect({
						name: 'package',
						title: 'Package',
						default: 'python',
						options: [
							{ name: 'Python', value: 'python' },
							{ name: 'Javascript', value: 'js' }
						]
					});

					var priority = new this.TopSelect({
						name: 'piority',
						title: 'Priority',
						options: [
							{ name: 'low', value: 0, className: 'priority-s' },
							{ name: 'medium', value: 1, className: 'priority-m' },
							{ name: 'high', value: 2, className: 'priority-l' }
						]
					});

					var config = new this.ToggleList({
						name: 'options',
						title: 'Options',
						extraOptions: true,
						options: [
							{
								name: 'no-injection',
								label: 'No Injection',
								description: 'Disable behavioral analysis.'
							},
							{
								name: 'process-memory-dump',
								label: 'Process Memory Dump',
								selected: true
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
								description: 'Enable simulated environment specified in the auxiliary configuration.',
								selected: true
							}
						]
					});

					var machine = new this.SimpleSelect({
						name: 'machine',
						title: 'Machine',
						default: 'default',
						options: [
							{ name: 'default', value: 'default' },
							{ name: 'Cuckoo1', value: 'Cuckoo1' },
							{ name: 'Cuckoo2', value: 'Cuckoo2' }
						]
					});

					// an array inside this array will render the elements in a split view
					form.add([network, [pkg, priority], config, machine]);
					form.draw();

				}
			}
		});

		$('#start-analysis').bind('click', function(e) {
			e.preventDefault();
			var json = analysis_ui.getData();
			console.log(json);
		});

	}

});