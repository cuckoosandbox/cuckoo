var gulp = require('gulp');
var gutil = require('gulp-util');
var sass = require('gulp-sass');
var sourcemaps = require('gulp-sourcemaps');
var autoprefixer = require('gulp-autoprefixer');
var clean = require('gulp-clean-css');
var notify = require('gulp-notify');

module.exports = function() {

  return gulp.src('./scss/main.scss')
    .pipe(sourcemaps.init())
    .pipe(sass({
      sourcemap: true,
			outputStyle: 'expanded',
			includePaths: [
				'./bower_components/font-awesome/scss',
				'./bower_components/font-roboto/src/styles'
			]
    }).on('error', sass.logError))
    .pipe(autoprefixer())
    .pipe(gutil.env.production ? gutil.noop() : sourcemaps.write('./'))
    .pipe(gutil.env.production ? clean() : gutil.noop())
    .pipe(notify('SCSS compiled to CSS!'))
    .pipe(gulp.dest('../static/css'));

}
