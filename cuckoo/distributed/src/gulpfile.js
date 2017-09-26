const path       = require('path');
const chalk      = require('chalk');
const gulp       = require('gulp');
const sass       = require('gulp-sass');
const browserify = require('browserify');
const babelify   = require('babelify');
const source     = require('vinyl-source-stream');
const buffer     = require('vinyl-buffer');

/*
  Sass rendering task
 */
gulp.task('sass', () => {
  return gulp.src('./scss/main.scss')
    .pipe(sass().on('error', sass.logError))
    .pipe(gulp.dest('../static/css'));
});

/*
  browserify/babelify task
 */
gulp.task('babel', () => {

  return browserify({
    entries: ['./scripts/main.babel'],
    extensions: ['.babel'],
    debug: true
  }).transform(babelify, {
    presets: ["env"],
    sourceRoot: './scripts/'
  }).bundle().on('error', err => {

    if(err.loc) {
      // assume typo error
      console.log(chalk.red('\nOopsie-daysee! You made an unforgivable typo:\n'));
      console.log(`${err.codeFrame}\n`);
      console.log(`>>> ${path.basename(err.fileName)} (line ${err.loc.line}, col ${err.loc.column} ]\n`);
    } else {
      // assume other error
      console.log(chalk.red(`${err}`));
    }

    this.emit('end');
  })
  .pipe(source('main.js'))
  .pipe(gulp.dest('../static/js'));

});

/*
  Gulp system watchers
 */
gulp.task('watch', () => {
  gulp.watch('scripts/**/*.babel', ['babel']);
  gulp.watch('scss/**/*.scss', ['sass']);
});

// default task: 'gulp'
gulp.task('default', ['watch']);
