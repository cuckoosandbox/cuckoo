(function e(t,n,r){function s(o,u){if(!n[o]){if(!t[o]){var a=typeof require=="function"&&require;if(!u&&a)return a(o,!0);if(i)return i(o,!0);var f=new Error("Cannot find module '"+o+"'");throw f.code="MODULE_NOT_FOUND",f}var l=n[o]={exports:{}};t[o][0].call(l.exports,function(e){var n=t[o][1][e];return s(n?n:e)},l,l.exports,e,t,n,r)}return n[o].exports}var i=typeof require=="function"&&require;for(var o=0;o<r.length;o++)s(r[o]);return s})({1:[function(require,module,exports){
"use strict";

},{}],2:[function(require,module,exports){
"use strict";

},{}],3:[function(require,module,exports){
'use strict';

var _FileTree = require('./components/FileTree');

var FileTree = _interopRequireWildcard(_FileTree);

var _Analysis = require('./components/Analysis');

var Analysis = _interopRequireWildcard(_Analysis);

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) newObj[key] = obj[key]; } } newObj.default = obj; return newObj; } }

// appends a helper to handlebars for humanizing sizes
Handlebars.registerHelper('file_size', function (text) {
	return new Handlebars.SafeString(FileTree.humanizeBytes(parseInt(text)));
});

$(function () {

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
				isDirectory: function isDirectory(item) {
					return item.type === 'directory';
				}
			},
			load: {
				url: '/api/real-file-structure',
				method: 'POST',
				params: {
					submit_id: 52
				},
				serialize: function serialize(response) {
					return response.data.files[0];
				}
			},
			transform: {
				file: function file(el, controller) {

					var self = this;

					// this = item
					var _$d = $(el).find('div');
					var size = FileTree.Label('size', FileTree.humanizeBytes(this.size));
					var info = FileTree.Label('info', '<i class="fa fa-info-circle"></i>', 'a');

					// adds the meta data
					_$d.append(info, size);

					$(info).on('click', function (e) {
						e.stopImmediatePropagation();
						controller.detailView(self);
					});

					return el;
				},

				folder: function folder(el, controller) {

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
			configure: function configure(form) {

				// this configuration allows for dynamic (yes, dynamic) forms

				var network = new this.TopSelect({
					name: 'network-routing',
					title: 'Network Routing',
					options: [{ name: 'none', value: 'none' }, { name: 'drop', value: 'drop' }, { name: 'internet', value: 'internet', selected: true }, { name: 'inetsim', value: 'inetsim' }, { name: 'tor', value: 'tor' }],
					extra_select: {
						title: 'VPN via',
						name: 'vpn',
						options: [{ name: 'France', value: 'FR-fr' }]
					}
				});

				var pkg = new this.SimpleSelect({
					name: 'package',
					title: 'Package',
					default: 'python',
					options: [{ name: 'Python', value: 'python' }, { name: 'Javascript', value: 'js' }]
				});

				var priority = new this.TopSelect({
					name: 'piority',
					title: 'Priority',
					options: [{ name: 'low', value: 0, className: 'priority-s' }, { name: 'medium', value: 1, className: 'priority-m' }, { name: 'high', value: 2, className: 'priority-l' }]
				});

				var config = new this.ToggleList({
					name: 'options',
					title: 'Options',
					extraOptions: true,
					options: [{
						name: 'no-injection',
						label: 'No Injection',
						description: 'Disable behavioral analysis.'
					}, {
						name: 'process-memory-dump',
						label: 'Process Memory Dump',
						selected: true
					}, {
						name: 'full-memory-dump',
						label: 'Full Memory Dump',
						description: 'If the “memory” processing module is enabled, will launch a Volatality Analysis.'
					}, {
						name: 'enforce-timeout',
						label: 'Enforce Timeout'
					}, {
						name: 'simulated-human-interaction',
						label: 'Enable Simulated Human Interaction',
						selected: true
					}, {
						name: 'enable-services',
						label: 'Enable Services',
						description: 'Enable simulated environment specified in the auxiliary configuration.',
						selected: true
					}]
				});

				var machine = new this.SimpleSelect({
					name: 'machine',
					title: 'Machine',
					default: 'default',
					options: [{ name: 'default', value: 'default' }, { name: 'Cuckoo1', value: 'Cuckoo1' }, { name: 'Cuckoo2', value: 'Cuckoo2' }]
				});

				// an array inside this array will render the elements in a split view
				form.add([network, [pkg, priority], config, machine]);
				form.draw();
			}
		}
	});

	$('#start-analysis').bind('click', function (e) {
		e.preventDefault();
		var json = analysis_ui.getData();
		console.log(json);
	});
});

},{"./components/Analysis":1,"./components/FileTree":2}]},{},[3])
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIm5vZGVfbW9kdWxlcy9icm93c2VyaWZ5L25vZGVfbW9kdWxlcy9icm93c2VyLXBhY2svX3ByZWx1ZGUuanMiLCJzY3JpcHRzL3N1Ym1pc3Npb24vY29tcG9uZW50cy9BbmFseXNpcy5qcyIsInNjcmlwdHMvc3VibWlzc2lvbi9jb21wb25lbnRzL0ZpbGVUcmVlLmpzIiwic2NyaXB0cy9zdWJtaXNzaW9uL3N1Ym1pc3Npb24uanMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6IkFBQUE7QUNBQTtBQUNBOztBQ0RBO0FBQ0E7Ozs7QUNEQTs7SUFBWSxROztBQUNaOztJQUFZLFE7Ozs7QUFFWjtBQUNBLFdBQVcsY0FBWCxDQUEwQixXQUExQixFQUF1QyxVQUFTLElBQVQsRUFBZTtBQUNyRCxRQUFPLElBQUksV0FBVyxVQUFmLENBQTBCLFNBQVMsYUFBVCxDQUF1QixTQUFTLElBQVQsQ0FBdkIsQ0FBMUIsQ0FBUDtBQUNBLENBRkQ7O0FBSUEsRUFBRSxZQUFXOztBQUVaO0FBQ0EsS0FBSSxjQUFjLElBQUksU0FBUyxpQkFBYixDQUErQjtBQUNoRCxhQUFXLFNBQVMsY0FBVCxDQUF3Qix3QkFBeEIsQ0FEcUM7QUFFaEQ7QUFDQSxZQUFVO0FBQ1QsV0FBUTtBQUNQLFdBQU8sVUFEQTtBQUVQLGdCQUFZLElBRkw7QUFHUCxhQUFTLFNBQVMsY0FBVCxDQUF3QixpQkFBeEIsQ0FIRjtBQUlQLGFBQVMsVUFKRixFQUljO0FBQ3JCLGlCQUFhLHFCQUFTLElBQVQsRUFBZTtBQUMzQixZQUFPLEtBQUssSUFBTCxLQUFjLFdBQXJCO0FBQ0E7QUFQTSxJQURDO0FBVVQsU0FBTTtBQUNMLFNBQUssMEJBREE7QUFFTCxZQUFRLE1BRkg7QUFHTCxZQUFRO0FBQ1AsZ0JBQVc7QUFESixLQUhIO0FBTUwsZUFBVyxtQkFBUyxRQUFULEVBQW1CO0FBQzdCLFlBQU8sU0FBUyxJQUFULENBQWMsS0FBZCxDQUFvQixDQUFwQixDQUFQO0FBQ0E7QUFSSSxJQVZHO0FBb0JULGNBQVc7QUFDVixV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cmF0ZWQuanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlc0NvbnRlbnQiOlsiKGZ1bmN0aW9uIGUodCxuLHIpe2Z1bmN0aW9uIHMobyx1KXtpZighbltvXSl7aWYoIXRbb10pe3ZhciBhPXR5cGVvZiByZXF1aXJlPT1cImZ1bmN0aW9uXCImJnJlcXVpcmU7aWYoIXUmJmEpcmV0dXJuIGEobywhMCk7aWYoaSlyZXR1cm4gaShvLCEwKTt2YXIgZj1uZXcgRXJyb3IoXCJDYW5ub3QgZmluZCBtb2R1bGUgJ1wiK28rXCInXCIpO3Rocm93IGYuY29kZT1cIk1PRFVMRV9OT1RfRk9VTkRcIixmfXZhciBsPW5bb109e2V4cG9ydHM6e319O3Rbb11bMF0uY2FsbChsLmV4cG9ydHMsZnVuY3Rpb24oZSl7dmFyIG49dFtvXVsxXVtlXTtyZXR1cm4gcyhuP246ZSl9LGwsbC5leHBvcnRzLGUsdCxuLHIpfXJldHVybiBuW29dLmV4cG9ydHN9dmFyIGk9dHlwZW9mIHJlcXVpcmU9PVwiZnVuY3Rpb25cIiYmcmVxdWlyZTtmb3IodmFyIG89MDtvPHIubGVuZ3RoO28rKylzKHJbb10pO3JldHVybiBzfSkiLCJcInVzZSBzdHJpY3RcIjtcbi8vIyBzb3VyY2VNYXBwaW5nVVJMPWRhdGE6YXBwbGljYXRpb24vanNvbjtiYXNlNjQsZXlKMlpYSnphVzl1SWpvekxDSnpiM1Z5WTJWeklqcGJYU3dpYm1GdFpYTWlPbHRkTENKdFlYQndhVzVuY3lJNklpSXNJbVpwYkdVaU9pSkJibUZzZVhOcGN5NXFjeUlzSW5OdmRYSmpaVkp2YjNRaU9pSXVMM05qY21sd2RITXZjM1ZpYldsemMybHZiaUlzSW5OdmRYSmpaWE5EYjI1MFpXNTBJanBiWFgwPSIsIlwidXNlIHN0cmljdFwiO1xuLy8jIHNvdXJjZU1hcHBpbmdVUkw9ZGF0YTphcHBsaWNhdGlvbi9qc29uO2Jhc2U2NCxleUoyWlhKemFXOXVJam96TENKemIzVnlZMlZ6SWpwYlhTd2libUZ0WlhNaU9sdGRMQ0p0WVhCd2FXNW5jeUk2SWlJc0ltWnBiR1VpT2lKR2FXeGxWSEpsWlM1cWN5SXNJbk52ZFhKalpWSnZiM1FpT2lJdUwzTmpjbWx3ZEhNdmMzVmliV2x6YzJsdmJpSXNJbk52ZFhKalpYTkRiMjUwWlc1MElqcGJYWDA9IiwiaW1wb3J0ICogYXMgRmlsZVRyZWUgZnJvbSAnLi9jb21wb25lbnRzL0ZpbGVUcmVlJztcbmltcG9ydCAqIGFzIEFuYWx5c2lzIGZyb20gJy4vY29tcG9uZW50cy9BbmFseXNpcyc7XG5cbi8vIGFwcGVuZHMgYSBoZWxwZXIgdG8gaGFuZGxlYmFycyBmb3IgaHVtYW5pemluZyBzaXplc1xuSGFuZGxlYmFycy5yZWdpc3RlckhlbHBlcignZmlsZV9zaXplJywgZnVuY3Rpb24odGV4dCkge1xuXHRyZXR1cm4gbmV3IEhhbmRsZWJhcnMuU2FmZVN0cmluZyhGaWxlVHJlZS5odW1hbml6ZUJ5dGVzKHBhcnNlSW50KHRleHQpKSk7XG59KTtcblxuJChmdW5jdGlvbigpIHtcblxuXHQvLyBjb2xsZWN0cyB0aGUgZW50aXJlIHVpIG9mIHRoaXMgcGFnZVxuXHR2YXIgYW5hbHlzaXNfdWkgPSBuZXcgQW5hbHlzaXMuQW5hbHlzaXNJbnRlcmZhY2Uoe1xuXHRcdGNvbnRhaW5lcjogZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2FuYWx5c2lzLWNvbmZpZ3VyYXRpb24nKSxcblx0XHQvLyBzcGVjaWZpZXMgdGhlIGZpbGUgdHJlZSBjb25maWd1cmF0aW9uXG5cdFx0ZmlsZXRyZWU6IHtcblx0XHRcdGNvbmZpZzoge1xuXHRcdFx0XHRsYWJlbDogJ2ZpbGV0cmVlJyxcblx0XHRcdFx0YXV0b0V4cGFuZDogdHJ1ZSxcblx0XHRcdFx0c2lkZWJhcjogZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2ZpbGV0cmVlLWRldGFpbCcpLFxuXHRcdFx0XHRuYW1lS2V5OiAnZmlsZW5hbWUnLCAvLyBuYW1lIG9mIHRoZSBmaWxlIG5hbWUgcHJvcGVydHlcblx0XHRcdFx0aXNEaXJlY3Rvcnk6IGZ1bmN0aW9uKGl0ZW0pIHtcblx0XHRcdFx0XHRyZXR1cm4gaXRlbS50eXBlID09PSAnZGlyZWN0b3J5Jztcblx0XHRcdFx0fVxuXHRcdFx0fSxcblx0XHRcdGxvYWQ6IHtcblx0XHRcdFx0dXJsOiAnL2FwaS9yZWFsLWZpbGUtc3RydWN0dXJlJyxcblx0XHRcdFx0bWV0aG9kOiAnUE9TVCcsXG5cdFx0XHRcdHBhcmFtczoge1xuXHRcdFx0XHRcdHN1Ym1pdF9pZDogNTJcblx0XHRcdFx0fSxcblx0XHRcdFx0c2VyaWFsaXplOiBmdW5jdGlvbihyZXNwb25zZSkge1xuXHRcdFx0XHRcdHJldHVybiByZXNwb25zZS5kYXRhLmZpbGVzWzBdO1xuXHRcdFx0XHR9XG5cdFx0XHR9LFxuXHRcdFx0dHJhbnNmb3JtOiB7XG5cdFx0XHRcdGZpbGU6IGZ1bmN0aW9uKGVsLCBjb250cm9sbGVyKSB7XG5cblx0XHRcdFx0XHR2YXIgc2VsZiA9IHRoaXM7XG5cblx0XHRcdFx0XHQvLyB0aGlzID0gaXRlbVxuXHRcdFx0XHRcdHZhciBfJGQgPSAkKGVsKS5maW5kKCdkaXYnKTtcblx0XHRcdFx0XHR2YXIgc2l6ZSA9IEZpbGVUcmVlLkxhYmVsKCdzaXplJywgRmlsZVRyZWUuaHVtYW5pemVCeXRlcyh0aGlzLnNpemUpKTsgXG5cdFx0XHRcdFx0dmFyIGluZm8gPSBGaWxlVHJlZS5MYWJlbCgnaW5mbycsICc8aSBjbGFzcz1cImZhIGZhLWluZm8tY2lyY2xlXCI+PC9pPicsICdhJyk7XG5cblx0XHRcdFx0XHQvLyBhZGRzIHRoZSBtZXRhIGRhdGFcblx0XHRcdFx0XHRfJGQuYXBwZW5kKGluZm8sIHNpemUpO1xuXG5cdFx0XHRcdFx0JChpbmZvKS5vbignY2xpY2snLCBmdW5jdGlvbihlKSB7XG5cdFx0XHRcdFx0XHRlLnN0b3BJbW1lZGlhdGVQcm9wYWdhdGlvbigpO1xuXHRcdFx0XHRcdFx0Y29udHJvbGxlci5kZXRhaWxWaWV3KHNlbGYpO1xuXHRcdFx0XHRcdH0pO1xuXG5cdFx0XHRcdFx0cmV0dXJuIGVsO1xuXHRcdFx0XHR9LFxuXG5cdFx0XHRcdGZvbGRlcjogZnVuY3Rpb24oZWwsIGNvbnRyb2xsZXIpIHtcblxuXHRcdFx0XHRcdHZhciBfJGQgPSAkKGVsKS5maW5kKCdkaXYnKTtcblx0XHRcdFx0XHR2YXIgc2l6ZSA9IEZpbGVUcmVlLkxhYmVsKCdzaXplJywgRmlsZVRyZWUuaHVtYW5pemVCeXRlcyhGaWxlVHJlZS5mb2xkZXJTaXplKHRoaXMpKSk7IFxuXHRcdFx0XHRcdF8kZC5hcHBlbmQoc2l6ZSk7XG5cblx0XHRcdFx0XHRyZXR1cm4gZWw7XG5cdFx0XHRcdH1cblx0XHRcdH1cblx0XHR9LFxuXG5cdFx0Ly8gc3BlY2lmaWVzIHRoZSBmb3JtIGNvbmZpZ3VyYXRpb25cblx0XHRmb3JtOiB7XG5cdFx0XHRjb250YWluZXI6IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdzdWJtaXNzaW9uLWNvbmZpZycpLFxuXHRcdFx0Y29uZmlndXJlOiBmdW5jdGlvbihmb3JtKSB7XG5cblx0XHRcdFx0Ly8gdGhpcyBjb25maWd1cmF0aW9uIGFsbG93cyBmb3IgZHluYW1pYyAoeWVzLCBkeW5hbWljKSBmb3Jtc1xuXG5cdFx0XHRcdHZhciBuZXR3b3JrID0gbmV3IHRoaXMuVG9wU2VsZWN0KHtcblx0XHRcdFx0XHRuYW1lOiAnbmV0d29yay1yb3V0aW5nJyxcblx0XHRcdFx0XHR0aXRsZTogJ05ldHdvcmsgUm91dGluZycsXG5cdFx0XHRcdFx0b3B0aW9uczogW1xuXHRcdFx0XHRcdFx0eyBuYW1lOidub25lJywgdmFsdWU6J25vbmUnIH0sXG5cdFx0XHRcdFx0XHR7IG5hbWU6J2Ryb3AnLCB2YWx1ZTonZHJvcCcgfSxcblx0XHRcdFx0XHRcdHsgbmFtZTonaW50ZXJuZXQnLCB2YWx1ZTonaW50ZXJuZXQnLCBzZWxlY3RlZDogdHJ1ZSB9LFxuXHRcdFx0XHRcdFx0eyBuYW1lOidpbmV0c2ltJywgdmFsdWU6J2luZXRzaW0nIH0sXG5cdFx0XHRcdFx0XHR7IG5hbWU6J3RvcicsIHZhbHVlOid0b3InIH1cblx0XHRcdFx0XHRdLFxuXHRcdFx0XHRcdGV4dHJhX3NlbGVjdDoge1xuXHRcdFx0XHRcdFx0dGl0bGU6ICdWUE4gdmlhJyxcblx0XHRcdFx0XHRcdG5hbWU6ICd2cG4nLFxuXHRcdFx0XHRcdFx0b3B0aW9uczogW1xuXHRcdFx0XHRcdFx0XHR7IG5hbWU6ICdGcmFuY2UnLCB2YWx1ZTogJ0ZSLWZyJyB9XG5cdFx0XHRcdFx0XHRdXG5cdFx0XHRcdFx0fVxuXHRcdFx0XHR9KTtcblxuXHRcdFx0XHR2YXIgcGtnID0gbmV3IHRoaXMuU2ltcGxlU2VsZWN0KHtcblx0XHRcdFx0XHRuYW1lOiAncGFja2FnZScsXG5cdFx0XHRcdFx0dGl0bGU6ICdQYWNrYWdlJyxcblx0XHRcdFx0XHRkZWZhdWx0OiAncHl0aG9uJyxcblx0XHRcdFx0XHRvcHRpb25zOiBbXG5cdFx0XHRcdFx0XHR7IG5hbWU6ICdQeXRob24nLCB2YWx1ZTogJ3B5dGhvbicgfSxcblx0XHRcdFx0XHRcdHsgbmFtZTogJ0phdmFzY3JpcHQnLCB2YWx1ZTogJ2pzJyB9XG5cdFx0XHRcdFx0XVxuXHRcdFx0XHR9KTtcblxuXHRcdFx0XHR2YXIgcHJpb3JpdHkgPSBuZXcgdGhpcy5Ub3BTZWxlY3Qoe1xuXHRcdFx0XHRcdG5hbWU6ICdwaW9yaXR5Jyxcblx0XHRcdFx0XHR0aXRsZTogJ1ByaW9yaXR5Jyxcblx0XHRcdFx0XHRvcHRpb25zOiBbXG5cdFx0XHRcdFx0XHR7IG5hbWU6ICdsb3cnLCB2YWx1ZTogMCwgY2xhc3NOYW1lOiAncHJpb3JpdHktcycgfSxcblx0XHRcdFx0XHRcdHsgbmFtZTogJ21lZGl1bScsIHZhbHVlOiAxLCBjbGFzc05hbWU6ICdwcmlvcml0eS1tJyB9LFxuXHRcdFx0XHRcdFx0eyBuYW1lOiAnaGlnaCcsIHZhbHVlOiAyLCBjbGFzc05hbWU6ICdwcmlvcml0eS1sJyB9XG5cdFx0XHRcdFx0XVxuXHRcdFx0XHR9KTtcblxuXHRcdFx0XHR2YXIgY29uZmlnID0gbmV3IHRoaXMuVG9nZ2xlTGlzdCh7XG5cdFx0XHRcdFx0bmFtZTogJ29wdGlvbnMnLFxuXHRcdFx0XHRcdHRpdGxlOiAnT3B0aW9ucycsXG5cdFx0XHRcdFx0ZXh0cmFPcHRpb25zOiB0cnVlLFxuXHRcdFx0XHRcdG9wdGlvbnM6IFtcblx0XHRcdFx0XHRcdHtcblx0XHRcdFx0XHRcdFx0bmFtZTogJ25vLWluamVjdGlvbicsXG5cdFx0XHRcdFx0XHRcdGxhYmVsOiAnTm8gSW5qZWN0aW9uJyxcblx0XHRcdFx0XHRcdFx0ZGVzY3JpcHRpb246ICdEaXNhYmxlIGJlaGF2aW9yYWwgYW5hbHlzaXMuJ1xuXHRcdFx0XHRcdFx0fSxcblx0XHRcdFx0XHRcdHtcblx0XHRcdFx0XHRcdFx0bmFtZTogJ3Byb2Nlc3MtbWVtb3J5LWR1bXAnLFxuXHRcdFx0XHRcdFx0XHRsYWJlbDogJ1Byb2Nlc3MgTWVtb3J5IER1bXAnLFxuXHRcdFx0XHRcdFx0XHRzZWxlY3RlZDogdHJ1ZVxuXHRcdFx0XHRcdFx0fSxcblx0XHRcdFx0XHRcdHtcblx0XHRcdFx0XHRcdFx0bmFtZTogJ2Z1bGwtbWVtb3J5LWR1bXAnLFxuXHRcdFx0XHRcdFx0XHRsYWJlbDogJ0Z1bGwgTWVtb3J5IER1bXAnLFxuXHRcdFx0XHRcdFx0XHRkZXNjcmlwdGlvbjogJ0lmIHRoZSDigJxtZW1vcnnigJ0gcHJvY2Vzc2luZyBtb2R1bGUgaXMgZW5hYmxlZCwgd2lsbCBsYXVuY2ggYSBWb2xhdGFsaXR5IEFuYWx5c2lzLidcblx0XHRcdFx0XHRcdH0sXG5cdFx0XHRcdFx0XHR7XG5cdFx0XHRcdFx0XHRcdG5hbWU6ICdlbmZvcmNlLXRpbWVvdXQnLFxuXHRcdFx0XHRcdFx0XHRsYWJlbDogJ0VuZm9yY2UgVGltZW91dCdcblx0XHRcdFx0XHRcdH0sXG5cdFx0XHRcdFx0XHR7XG5cdFx0XHRcdFx0XHRcdG5hbWU6ICdzaW11bGF0ZWQtaHVtYW4taW50ZXJhY3Rpb24nLFxuXHRcdFx0XHRcdFx0XHRsYWJlbDogJ0VuYWJsZSBTaW11bGF0ZWQgSHVtYW4gSW50ZXJhY3Rpb24nLFxuXHRcdFx0XHRcdFx0XHRzZWxlY3RlZDogdHJ1ZVxuXHRcdFx0XHRcdFx0fSxcblx0XHRcdFx0XHRcdHtcblx0XHRcdFx0XHRcdFx0bmFtZTogJ2VuYWJsZS1zZXJ2aWNlcycsXG5cdFx0XHRcdFx0XHRcdGxhYmVsOiAnRW5hYmxlIFNlcnZpY2VzJyxcblx0XHRcdFx0XHRcdFx0ZGVzY3JpcHRpb246ICdFbmFibGUgc2ltdWxhdGVkIGVudmlyb25tZW50IHNwZWNpZmllZCBpbiB0aGUgYXV4aWxpYXJ5IGNvbmZpZ3VyYXRpb24uJyxcblx0XHRcdFx0XHRcdFx0c2VsZWN0ZWQ6IHRydWVcblx0XHRcdFx0XHRcdH1cblx0XHRcdFx0XHRdXG5cdFx0XHRcdH0pO1xuXG5cdFx0XHRcdHZhciBtYWNoaW5lID0gbmV3IHRoaXMuU2ltcGxlU2VsZWN0KHtcblx0XHRcdFx0XHRuYW1lOiAnbWFjaGluZScsXG5cdFx0XHRcdFx0dGl0bGU6ICdNYWNoaW5lJyxcblx0XHRcdFx0XHRkZWZhdWx0OiAnZGVmYXVsdCcsXG5cdFx0XHRcdFx0b3B0aW9uczogW1xuXHRcdFx0XHRcdFx0eyBuYW1lOiAnZGVmYXVsdCcsIHZhbHVlOiAnZGVmYXVsdCcgfSxcblx0XHRcdFx0XHRcdHsgbmFtZTogJ0N1Y2tvbzEnLCB2YWx1ZTogJ0N1Y2tvbzEnIH0sXG5cdFx0XHRcdFx0XHR7IG5hbWU6ICdDdWNrb28yJywgdmFsdWU6ICdDdWNrb28yJyB9XG5cdFx0XHRcdFx0XVxuXHRcdFx0XHR9KTtcblxuXHRcdFx0XHQvLyBhbiBhcnJheSBpbnNpZGUgdGhpcyBhcnJheSB3aWxsIHJlbmRlciB0aGUgZWxlbWVudHMgaW4gYSBzcGxpdCB2aWV3XG5cdFx0XHRcdGZvcm0uYWRkKFtuZXR3b3JrLCBbcGtnLCBwcmlvcml0eV0sIGNvbmZpZywgbWFjaGluZV0pO1xuXHRcdFx0XHRmb3JtLmRyYXcoKTtcblxuXHRcdFx0fVxuXHRcdH1cblx0fSk7XG5cblx0JCgnI3N0YXJ0LWFuYWx5c2lzJykuYmluZCgnY2xpY2snLCBmdW5jdGlvbihlKSB7XG5cdFx0ZS5wcmV2ZW50RGVmYXVsdCgpO1xuXHRcdHZhciBqc29uID0gYW5hbHlzaXNfdWkuZ2V0RGF0YSgpO1xuXHRcdGNvbnNvbGUubG9nKGpzb24pO1xuXHR9KTtcblxufSk7Il19
