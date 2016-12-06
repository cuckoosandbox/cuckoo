var gulp 	= require('gulp');
var assets 	= require('gulp-bower-assets');

/**
 * BOWER task
 * @description: hooks up bower files using gulp-bower-assets
 */
module.exports = function() {

	// select the assets.json file for parsing
	return gulp.src('assets.json')

	// run gulp-bower-assets to concat the bower files
	.pipe(assets({
		prefix: false
	}))

	// output to vendor folder in the assets directory of dit
	.pipe(gulp.dest('../static'));

}