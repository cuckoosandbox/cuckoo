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
	gulp.watch('./scss/**/*.scss', ['styles']);
}