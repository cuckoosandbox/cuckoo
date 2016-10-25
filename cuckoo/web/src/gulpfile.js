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
gulp.task('default', ['styles','watch']);

// task for ONLY building to static
gulp.task('build', ['styles']);