var path       = require('path');
var chalk      = require('chalk');
var gulp       = require('gulp');
var sass       = require('gulp-sass');
var browserify = require('browserify');
var babelify   = require('babelify');
var source     = require('vinyl-source-stream');
var buffer     = require('vinyl-buffer');

// scss packages as node wrappers for sass.includePaths
var bourbon    = require('bourbon');

/*
  Sass rendering task
 */
gulp.task('sass', function() {
  return gulp.src('./scss/main.scss')
    .pipe(sass({
      sourceMap: true,
      includePaths: [
        require('bourbon').includePaths,
        __dirname + '/node_modules'
      ]
    }).on('error', sass.logError))
    .pipe(gulp.dest('../static/css'));
});

/*
  browserify/babelify task
 */
gulp.task('babel', function() {

  var b = browserify({
		entries: ['./scripts/main.babel'],
		extensions: ['.babel'],
		debug: true
	});

  // require global dependencies
  b.require(__dirname + '/node_modules/jquery/dist/jquery.js', { expose: 'jquery' });

  return b.transform("babelify", {
		extensions: ['.babel'],
		presets: ["es2015"],
		sourceRoot: './scripts/'
	}).bundle().on('error', function(err) {
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

	}).pipe(source('main.js'))
		.pipe(buffer())
		.pipe(gulp.dest('../static/js'));

});

/*
  Gulp system watchers
 */
gulp.task('watch', function() {
  gulp.watch('./scripts/**/*.babel', ['babel']);
  gulp.watch('./scss/**/*.scss', ['sass']);
});

// default task: 'gulp'
gulp.task('default', ['watch']);
