var gulp          = require('gulp');
var gutil         = require('gulp-util');
var sass          = require('gulp-sass');
var sourcemaps    = require('gulp-sourcemaps');
var autoprefixer  = require('gulp-autoprefixer');
var notify        = require('gulp-notify');
var comb          = require('gulp-csscomb');

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
    .pipe(comb({
      "remove-empty-rulesets": true,
      "always-semicolon": true,
      "color-case": "lower",
      "block-indent": "",
      "color-shorthand": false,
      "element-case": "lower",
      "eof-newline": true,
      "leading-zero": true,
      "quotes": "double",
      "sort-order-fallback": "abc",
      "space-before-colon": "",
      "space-after-colon": " ",
      "space-before-combinator": " ",
      "space-after-combinator": " ",
      "space-between-declarations": "\n",
      "space-before-opening-brace": " ",
      "space-after-opening-brace": "\n",
      "space-after-selector-delimiter": "\n",
      "space-before-selector-delimiter": "",
      "space-before-closing-brace": "\n",
      "strip-spaces": true,
      "tab-size": false,
      "vendor-prefix-align": true
    }))
    .pipe(gutil.env.production ? gutil.noop() : sourcemaps.write('./'))
    .pipe(notify('SCSS compiled to CSS!'))
    .pipe(gulp.dest('../static/css'));

}
