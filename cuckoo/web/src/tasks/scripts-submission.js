var fs = require('fs');
var gulp = require('gulp');
var gutil = require('gulp-util');
var sourcemaps = require('gulp-sourcemaps');
var browserify = require('browserify');
var babelify = require('babelify');
var source = require('vinyl-source-stream');
var buffer = require('vinyl-buffer');
var uglify = require('gulp-uglify');

module.exports = function() {

	browserify({
			entries: ['./scripts/submission/submission.js'],
			extensions: ['.js'],
			debug: true
		})
		.transform(babelify, {
			extensions: ['.js'],
			presets: ["es2015"],
			sourceRoot: './scripts/submission'
		})
		.bundle()
		.on('error', function(err) { console.log(err); })
		.pipe(source('submission.js'))
		.pipe(buffer())
		.pipe(sourcemaps.init({loadMaps: true}))
		.pipe(sourcemaps.write('./'))
		.pipe(gulp.dest('../static/js/cuckoo'));

}
