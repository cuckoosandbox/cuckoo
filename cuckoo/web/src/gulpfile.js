/*
   Copyright (C) 2016 Cuckoo Foundation.
   This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
   see the file 'docs/LICENSE' for copying permission.
 */

/*
	require dependencies:
		gulp
		gulp-task-loader
 */
var gulp = require('gulp');

/*
	this script will read all modules in ./tasks and executes them
	as gulp task functions. All tasks can be used here by their names.
 */
require('gulp-task-loader')('./tasks');

// define the default task when 'gulp' is called from the CLI
gulp.task('default', ['bower','styles','scripts','scripts-submission','scripts-rdp','handlebars','watch']);

// task for ONLY building to static
gulp.task('build', ['bower','styles','scripts','scripts-submission','scripts-rdp','handlebars','build-guac']);
