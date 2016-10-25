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