class AnalysisSidebar {

	constructor(_$) {
		this.$ = _$;
		this.open = false;

		this.activateListeners();
	}

	activateListeners() {

		this.$.bind('mouseenter', function(e) {
			this.onMouseEnter(e);
		}.bind(this)).bind('mouseleave', function(e) {
			this.onMouseOut(e);
		}.bind(this));

	}

	onMouseEnter(e) {
		this.$.addClass('open');
	}

	onMouseOut(e) {
		this.$.removeClass('open');
	}

}

$(function() {

	var sidebar = new AnalysisSidebar($('#analysis-nav'));
	console.log(sidebar);

});