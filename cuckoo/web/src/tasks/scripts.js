var gulp = require('gulp');
var gutil = require('gulp-util');
var browserify = require('browserify');
var babelify = require('babelify');
var babel = require('gulp-babel');
var source = require('vinyl-source-stream');
var buffer = require('vinyl-buffer');
var sourcemaps = require('gulp-sourcemaps');
var uglify = require('gulp-uglify');

module.exports = function(done) {

	var stream = gulp.src(['scripts/**/*.js', '!scripts/submission/**'])
		.pipe(sourcemaps.init())
		.pipe(babel({
			presets: 'es2015'
		}))
		.pipe(gutil.env.production ? uglify() : gutil.noop())
		.pipe(sourcemaps.write('.'))
		.pipe(gulp.dest('../static/js/cuckoo'));

}