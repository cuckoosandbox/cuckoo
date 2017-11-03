var CONFIG = {

  // configures the to-concat javascript library paths, relative
  // to the node_modules folder. (this gets corrected automagically)
  // later on.
  javascriptLibraryPaths: [
    'lodash/lodash.js',
    'moment/moment.js',
    'humanize-plus/dist/humanize.js',
    'jquery/dist/jquery.js',
    'jquery-ui-bundle/jquery-ui.js',
    'gridstack/dist/gridstack.js',
    'gridstack/dist/gridstack.jQueryUI.js',
    'chart.js/dist/Chart.bundle.js'
  ]

}

var fs         = require('fs');
var path       = require('path');
var chalk      = require('chalk');
var gulp       = require('gulp');
var sass       = require('gulp-sass');
var browserify = require('browserify');
var babelify   = require('babelify');
var source     = require('vinyl-source-stream');
var buffer     = require('vinyl-buffer');
var concat     = require('gulp-concat');
var cleanCSS   = require('gulp-clean-css');
var uglify     = require('gulp-uglify');
var pump       = require('pump');

// scss packages as node wrappers for sass.includePaths
var bourbon    = require('bourbon');

// shortcut
function _modulePath(modulePath) {
  var p = path.resolve(__dirname + '/node_modules/' + modulePath);
  if(!fs.existsSync(p)) {
    console.log('`'+p+'` does not exist :( please try npm-installing this package and try again.');
    return false;
  } else {
    return p;
  }
}

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
  Utility concatenation of library files
  */
gulp.task('lib', function() {

  var MAPPED_JAVASCRIPT_LIBRARIES = CONFIG.javascriptLibraryPaths.map(function(lib) {
    return _modulePath(lib);
  }).filter(function(lib) {
    return lib !== false;
  });

  gulp.src(MAPPED_JAVASCRIPT_LIBRARIES)
    .pipe(concat('lib.js'))
    .pipe(gulp.dest('../static/js'));

});

/*
  Gulp system watchers
 */
gulp.task('watch', function() {
  gulp.watch('./scripts/**/*.babel', ['babel']);
  gulp.watch('./scss/**/*.scss', ['sass']);
});

gulp.task('minify-css', function() {

  gulp.src('../static/css/*.css')
    .pipe(cleanCSS())
    .pipe(gulp.dest('../static/css'));

});

gulp.task('minify-js', function(cb) {

  pump([
    gulp.src('../static/js/*.js'),
    uglify(),
    gulp.dest('../static/js')
  ], cb);

});

/*
  Compress all the sources in a single task
 */
gulp.task('compress', ['minify-css','minify-js']);

// default task: 'gulp'
gulp.task('default', ['watch']);
