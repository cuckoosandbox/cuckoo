/* 
   Copyright (C) 2016 Cuckoo Foundation.
   This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
   see the file 'docs/LICENSE' for copying permission.
 */

/*
	require node dependencies:
		gulp
		gulp-ruby-sass
		gulp-sourcemaps
 */
var gulp 		= require('gulp');
var sass 		= require('gulp-ruby-sass');
var sourcemaps 	= require('gulp-sourcemaps');
var insert 		= require('gulp-insert');

/*
	return Gulp function()
	- cursor to main.scss
	- catch errors and display
	- write sourcemaps for easy css debugging in the browser
 */
module.exports = function() {

	return sass('./scss/main.scss', { 
			sourcemap: true, 
			style: 'expanded' 
		})
		// enables verbose logging of SASS errors
		.on('error', sass.logError)
		// adds a copyright notice to the top of the compiled document
		// .pipe(insert.transform(function(contents) {
		// 	return "/* \n\n\t Copyright (C) "+ new Date().getFullYear() +" Cuckoo Foundation.\n\t This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org \n\t see the file 'docs/LICENSE' for copying permission \n\n */ \n\n " + contents;
		// }))
		// writes the sourcemap
		.pipe(sourcemaps.write())
		// output file to static web dir
		.pipe(gulp.dest('../static/css'));

}