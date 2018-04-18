/*
   Copyright (C) 2016 Cuckoo Foundation.
   This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
   see the file 'docs/LICENSE' for copying permission.
 */

/*
	require node dependencies:
		gulp
		gulp-watch
 */
var gulp = require('gulp');
var watch = require('gulp-watch');

/*
	return Gulp function()
	- initiates watchers for static building
 */
module.exports = function() {
	// starts a watcher RECURSIVE on all .scss files in /src/scss and assigns 'styles' as task
	gulp.watch('scss/**/*.scss', ['styles']);
	gulp.watch(['scripts/**/*.js','!scripts/submission/**/*.js'], ['scripts']);
	gulp.watch('scripts/submission/**/*.js', ['scripts-submission']);
	gulp.watch(['scripts/rdp/**/*.js', '!guac/**/*'], ['scripts-rdp']);
	gulp.watch('handlebars/**/*.hbs', ['handlebars']);
}
