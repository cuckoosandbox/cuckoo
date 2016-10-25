/*
	require node dependencies:
		gulp
		gulp-ruby-sass
		gulp-sourcemaps
 */
var gulp 		= require('gulp');
var sass 		= require('gulp-ruby-sass');
var sourcemaps 	= require('gulp-sourcemaps');

/*
	return Gulp function()
	- cursor to main.scss
	- catch errors and display
	- write sourcemaps for easy css debugging in the browser
 */
module.exports = function() {

	return sass('./scss/main.scss', { sourcemap: true })
		.on('error', sass.logError)
		.pipe(sourcemaps.write())
		.pipe(gulp.dest('../static/css'));

}