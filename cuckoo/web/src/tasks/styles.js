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
var gulp 		 = require('gulp');
var gutil 		 = require('gulp-util');
var sass 		 = require('gulp-ruby-sass');
var sourcemaps 	 = require('gulp-sourcemaps');
var insert 		 = require('gulp-insert');
var clean 		 = require('gulp-clean-css');
var notify 		 = require('gulp-notify');
var autoprefixer = require('gulp-autoprefixer');

/*
	return Gulp function()
	- cursor to main.scss
	- catch errors and display
	- write sourcemaps for easy css debugging in the browser
 */
module.exports = function() {

	return sass('./scss/main.scss', { 
			sourcemap: true, 
			style: 'expanded',
			loadPath: [
				'./bower_components/font-awesome/scss',
				'./bower_components/font-roboto/src/styles'
			]
		})
		// enables verbose logging of SASS errors
		.on('error', sass.logError)
		// adds a copyright notice to the top of the compiled document
		// .pipe(insert.transform(function(contents) {
		// 	return "/* \n\n\t Copyright (C) "+ new Date().getFullYear() +" Cuckoo Foundation.\n\t This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org \n\t see the file 'docs/LICENSE' for copying permission \n\n */ \n\n " + contents;
		// }))
		// writes the sourcemap
		.pipe(autoprefixer())
		.pipe(gutil.env.production ? gutil.noop() : sourcemaps.write('./'))
		.pipe(gutil.env.production ? clean() : gutil.noop())
		.pipe(notify('SCSS compiled to CSS!'))

		// output file to static web dir
		.pipe(gulp.dest('../static/css'));

}