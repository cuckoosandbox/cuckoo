var gulp = require('gulp');
var browserify = require('browserify');
var babelify = require('babelify');
var babel = require('gulp-babel');
var source = require('vinyl-source-stream');
var buffer = require('vinyl-buffer');
var sourcemaps = require('gulp-sourcemaps');

module.exports = function(done) {

	return gulp.src(['scripts/**/*.js', '!scripts/submission/**/*.js'])
		.pipe(sourcemaps.init())
		.pipe(babel({
			presets: 'es2015'
		}))
		.pipe(sourcemaps.write('.'))
		.pipe(gulp.dest('../static/js/cuckoo'));

}