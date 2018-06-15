var path = require('path');
var gulp = require('gulp');
var gutil = require('gulp-util');
var browserify = require('browserify');
var babelify = require('babelify');
var babel = require('gulp-babel');
var source = require('vinyl-source-stream');
var buffer = require('vinyl-buffer');
var sourcemaps = require('gulp-sourcemaps');
var uglify = require('gulp-uglify');
var chalk = require('chalk');
var debug = require('gulp-debug');
var notify = require('gulp-notify');

module.exports = function(done) {

	gulp.src(['scripts/*.js'])
		.pipe(sourcemaps.init())
		.pipe(babel({
			presets: 'es2015'
		}))
		.on('error', function(err) {
			console.log(chalk.red('\nOopsie-daysee! You made an unforgivable typo:\n'));
			console.log(`${err.codeFrame}\n`);
			console.log(`>>> ${path.basename(err.fileName)} (line ${err.loc.line}, col ${err.loc.column} ]\n`);
			this.emit('end');
		})
		.pipe(sourcemaps.write('.'))
		.pipe(gulp.dest('../static/js/cuckoo'));

	done();

}
