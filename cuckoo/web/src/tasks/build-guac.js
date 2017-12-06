var gulp = require('gulp');
var concat = require('gulp-concat');

/*
  Build the guacamole client source and export to static for inclusion.

  - when there is an update, drag common-js files in to the /guac folder
    and run 'gulp build-guac' to compile to static.

 */

module.exports = function() {
  return gulp.src('scripts/rdp/guac/*.js')
    .pipe(concat('guac.js'))
    .pipe(gulp.dest('../static/js'));
}
