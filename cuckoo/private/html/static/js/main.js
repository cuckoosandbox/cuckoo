$(function() {

	$('[data-init=table]').each(function() {
		UIKit.TableController($(this));
	});

	$('[data-init="collapse"]').each(function() {
		UIKit.Collapsable($(this));
	});

});