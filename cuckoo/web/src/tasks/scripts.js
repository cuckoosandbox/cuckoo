var gulp = require('gulp');
var babel = require('gulp-babel');
var sourcemaps = require('gulp-sourcemaps');

module.exports = function(done) {

	return gulp.src('./scripts/**/*.js')
		.pipe(sourcemaps.init())
		.pipe(babel({
			presets: 'es2015'
		}))
		.pipe(sourcemaps.write('.'))
		.pipe(gulp.dest('../static/js/cuckoo'));

}