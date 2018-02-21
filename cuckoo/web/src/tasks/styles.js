var gulp          = require('gulp');
var gutil         = require('gulp-util');
var sass          = require('gulp-sass');
var sourcemaps    = require('gulp-sourcemaps');
var autoprefixer  = require('gulp-autoprefixer');
var notify        = require('gulp-notify');
var comb          = require('gulp-csscomb');

// alias for prefixing bower urls
function bower(path) {
  return './bower_components/' + path;
}

module.exports = function() {

  return gulp.src('./scss/main.scss')
    .pipe(sourcemaps.init())
    .pipe(sass({
      sourcemap: true,
			outputStyle: 'expanded',
			includePaths: [
				bower('font-awesome/scss'),
				bower('font-roboto/src/styles'),
        bower('bourbon/app/assets/stylesheets')
			]
    }).on('error', sass.logError))
    .pipe(autoprefixer({
      browsers: ['last 2 versions'],
      cascade: false
    }))
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
    .pipe(sourcemaps.write('./'))
    .pipe(notify('SCSS compiled to CSS!'))
    .pipe(gulp.dest('../static/css'));

}
