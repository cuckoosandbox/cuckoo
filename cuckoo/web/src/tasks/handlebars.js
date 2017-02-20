var gulp 		= require('gulp');
var handlebars 	= require('gulp-handlebars');
var concat  	= require('gulp-concat');
var declare 	= require('gulp-declare');
var wrap 		= require('gulp-wrap');

module.exports = function() {

	return gulp.src('./handlebars/*.hbs')
		.pipe(handlebars())
		.pipe(wrap('Handlebars.template(<%= contents %>)'))
		.pipe(declare({
			namespace: 'HANDLEBARS_TEMPLATES',
			noRedeclare: true
		}))
		.pipe(concat('handlebars-templates.js'))
		.pipe(gulp.dest('../static/js'));

}