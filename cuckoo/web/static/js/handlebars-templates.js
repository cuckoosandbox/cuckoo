this["HANDLEBARS_TEMPLATES"] = this["HANDLEBARS_TEMPLATES"] || {};
this["HANDLEBARS_TEMPLATES"]["control-simple-select"] = Handlebars.template({"1":function(depth0,helpers,partials,data) {
    var helper;

  return "<a href=\""
    + this.escapeExpression(((helper = (helper = helpers.doc_link || (depth0 != null ? depth0.doc_link : depth0)) != null ? helper : helpers.helperMissing),(typeof helper === "function" ? helper.call(depth0,{"name":"doc_link","hash":{},"data":data}) : helper)))
    + "\" target=\"_blank\"><i class=\"fa fa-info-circle\"></i></a>";
},"3":function(depth0,helpers,partials,data) {
    var stack1, helper, alias1=helpers.helperMissing, alias2="function", alias3=this.escapeExpression;

  return "				<option value=\""
    + alias3(((helper = (helper = helpers.value || (depth0 != null ? depth0.value : depth0)) != null ? helper : alias1),(typeof helper === alias2 ? helper.call(depth0,{"name":"value","hash":{},"data":data}) : helper)))
    + "\" "
    + ((stack1 = helpers['if'].call(depth0,(depth0 != null ? depth0.selected : depth0),{"name":"if","hash":{},"fn":this.program(4, data, 0),"inverse":this.noop,"data":data})) != null ? stack1 : "")
    + ">"
    + alias3(((helper = (helper = helpers.name || (depth0 != null ? depth0.name : depth0)) != null ? helper : alias1),(typeof helper === alias2 ? helper.call(depth0,{"name":"name","hash":{},"data":data}) : helper)))
    + "</option>\n";
},"4":function(depth0,helpers,partials,data) {
    return "selected";
},"compiler":[6,">= 2.0.0-beta.1"],"main":function(depth0,helpers,partials,data) {
    var stack1, helper, alias1=helpers.helperMissing, alias2="function", alias3=this.escapeExpression;

  return "	<legend class=\"flex-form__field-title\">"
    + alias3(((helper = (helper = helpers.title || (depth0 != null ? depth0.title : depth0)) != null ? helper : alias1),(typeof helper === alias2 ? helper.call(depth0,{"name":"title","hash":{},"data":data}) : helper)))
    + " "
    + ((stack1 = helpers['if'].call(depth0,(depth0 != null ? depth0.doc_link : depth0),{"name":"if","hash":{},"fn":this.program(1, data, 0),"inverse":this.noop,"data":data})) != null ? stack1 : "")
    + "</legend>\n	<div class=\"flex-form__select\">\n		<select name=\""
    + alias3(((helper = (helper = helpers.name || (depth0 != null ? depth0.name : depth0)) != null ? helper : alias1),(typeof helper === alias2 ? helper.call(depth0,{"name":"name","hash":{},"data":data}) : helper)))
    + "\">\n"
    + ((stack1 = helpers.each.call(depth0,(depth0 != null ? depth0.options : depth0),{"name":"each","hash":{},"fn":this.program(3, data, 0),"inverse":this.noop,"data":data})) != null ? stack1 : "")
    + "		</select>\n		<i class=\"fa fa-chevron-down\"></i>\n	</div>";
},"useData":true});
this["HANDLEBARS_TEMPLATES"]["control-toggle-list"] = Handlebars.template({"1":function(depth0,helpers,partials,data) {
    var helper;

  return "<a href=\""
    + this.escapeExpression(((helper = (helper = helpers.doc_link || (depth0 != null ? depth0.doc_link : depth0)) != null ? helper : helpers.helperMissing),(typeof helper === "function" ? helper.call(depth0,{"name":"doc_link","hash":{},"data":data}) : helper)))
    + "\" target=\"_blank\"><i class=\"fa fa-info-circle\"></i></a>";
},"3":function(depth0,helpers,partials,data,blockParams,depths) {
    var stack1, helper, alias1=helpers.helperMissing, alias2="function", alias3=this.escapeExpression, alias4=this.lambda;

  return "		<li>\n			<p>"
    + alias3(((helper = (helper = helpers.label || (depth0 != null ? depth0.label : depth0)) != null ? helper : alias1),(typeof helper === alias2 ? helper.call(depth0,{"name":"label","hash":{},"data":data}) : helper)))
    + " "
    + ((stack1 = helpers['if'].call(depth0,(depth0 != null ? depth0.description : depth0),{"name":"if","hash":{},"fn":this.program(4, data, 0, blockParams, depths),"inverse":this.noop,"data":data})) != null ? stack1 : "")
    + "</p>\n			<label for=\""
    + alias3(alias4((depths[1] != null ? depths[1].name : depths[1]), depth0))
    + "-"
    + alias3(((helper = (helper = helpers.name || (depth0 != null ? depth0.name : depth0)) != null ? helper : alias1),(typeof helper === alias2 ? helper.call(depth0,{"name":"name","hash":{},"data":data}) : helper)))
    + "\" class=\"flex-form__toggle-list-switch\">\n				<input type=\"checkbox\" id=\""
    + alias3(alias4((depths[1] != null ? depths[1].name : depths[1]), depth0))
    + "-"
    + alias3(((helper = (helper = helpers.name || (depth0 != null ? depth0.name : depth0)) != null ? helper : alias1),(typeof helper === alias2 ? helper.call(depth0,{"name":"name","hash":{},"data":data}) : helper)))
    + "\" name=\""
    + alias3(alias4((depths[1] != null ? depths[1].name : depths[1]), depth0))
    + "\" "
    + ((stack1 = helpers['if'].call(depth0,(depth0 != null ? depth0.selected : depth0),{"name":"if","hash":{},"fn":this.program(6, data, 0, blockParams, depths),"inverse":this.noop,"data":data})) != null ? stack1 : "")
    + " data-option=\""
    + alias3(((helper = (helper = helpers.name || (depth0 != null ? depth0.name : depth0)) != null ? helper : alias1),(typeof helper === alias2 ? helper.call(depth0,{"name":"name","hash":{},"data":data}) : helper)))
    + "\" />\n				<span></span>\n			</label>\n		</li>\n";
},"4":function(depth0,helpers,partials,data) {
    var helper;

  return "<span>"
    + this.escapeExpression(((helper = (helper = helpers.description || (depth0 != null ? depth0.description : depth0)) != null ? helper : helpers.helperMissing),(typeof helper === "function" ? helper.call(depth0,{"name":"description","hash":{},"data":data}) : helper)))
    + "</span>";
},"6":function(depth0,helpers,partials,data) {
    return "checked";
},"8":function(depth0,helpers,partials,data) {
    return "		<li class=\"toggle-list-seperator\">\n			<p>Extra options <span><a href=\"https://cuckoo.sh/docs/usage/packages.html\" target=\"_blank\">What can I use?</a></span></p>\n		</li>\n		<li class=\"flex-form__table extra-options\">\n			<table>\n				<thead>\n					<tr>\n						<th>name</th>\n						<th>value</th>\n					</tr>\n				</thead>\n				<tfoot>\n					<tr>\n						<td><input type=\"text\" placeholder=\"name\" name=\"new-key\" /></td>\n						<td><input type=\"text\" placeholder=\"value\" name=\"new-value\" /></td>\n					</tr>\n				</tfoot>\n				<tbody></tbody>\n			</table>\n		</li>\n\n";
},"10":function(depth0,helpers,partials,data) {
    return "	<p class=\"description\">To add a new option, type the option name + value and hit enter. it will add itself to the list. Remove an item by clicking the right remove icon.</p>\n";
},"compiler":[6,">= 2.0.0-beta.1"],"main":function(depth0,helpers,partials,data,blockParams,depths) {
    var stack1, helper;

  return "<legend class=\"flex-form__field-title\">"
    + this.escapeExpression(((helper = (helper = helpers.title || (depth0 != null ? depth0.title : depth0)) != null ? helper : helpers.helperMissing),(typeof helper === "function" ? helper.call(depth0,{"name":"title","hash":{},"data":data}) : helper)))
    + " "
    + ((stack1 = helpers['if'].call(depth0,(depth0 != null ? depth0.doc_link : depth0),{"name":"if","hash":{},"fn":this.program(1, data, 0, blockParams, depths),"inverse":this.noop,"data":data})) != null ? stack1 : "")
    + "</legend>\n<ul class=\"flex-form__toggle-list\">\n"
    + ((stack1 = helpers.each.call(depth0,(depth0 != null ? depth0.options : depth0),{"name":"each","hash":{},"fn":this.program(3, data, 0, blockParams, depths),"inverse":this.noop,"data":data})) != null ? stack1 : "")
    + "	\n"
    + ((stack1 = helpers['if'].call(depth0,(depth0 != null ? depth0.extraOptions : depth0),{"name":"if","hash":{},"fn":this.program(8, data, 0, blockParams, depths),"inverse":this.noop,"data":data})) != null ? stack1 : "")
    + "</ul>\n"
    + ((stack1 = helpers['if'].call(depth0,(depth0 != null ? depth0.extraOptions : depth0),{"name":"if","hash":{},"fn":this.program(10, data, 0, blockParams, depths),"inverse":this.noop,"data":data})) != null ? stack1 : "");
},"useData":true,"useDepths":true});
this["HANDLEBARS_TEMPLATES"]["control-top-select"] = Handlebars.template({"1":function(depth0,helpers,partials,data) {
    var helper;

  return "<a href=\""
    + this.escapeExpression(((helper = (helper = helpers.doc_link || (depth0 != null ? depth0.doc_link : depth0)) != null ? helper : helpers.helperMissing),(typeof helper === "function" ? helper.call(depth0,{"name":"doc_link","hash":{},"data":data}) : helper)))
    + "\" target=\"_blank\"><i class=\"fa fa-info-circle\"></i></a>";
},"3":function(depth0,helpers,partials,data,blockParams,depths) {
    var stack1;

  return "		<li class=\""
    + ((stack1 = helpers['if'].call(depth0,(depth0 != null ? depth0.description : depth0),{"name":"if","hash":{},"fn":this.program(4, data, 0, blockParams, depths),"inverse":this.noop,"data":data})) != null ? stack1 : "")
    + " "
    + ((stack1 = helpers['if'].call(depth0,(depth0 != null ? depth0.disabled : depth0),{"name":"if","hash":{},"fn":this.program(6, data, 0, blockParams, depths),"inverse":this.noop,"data":data})) != null ? stack1 : "")
    + "\">\n"
    + ((stack1 = helpers.unless.call(depth0,(depth0 != null ? depth0.manual : depth0),{"name":"unless","hash":{},"fn":this.program(8, data, 0, blockParams, depths),"inverse":this.program(15, data, 0, blockParams, depths),"data":data})) != null ? stack1 : "")
    + "		</li>\n";
},"4":function(depth0,helpers,partials,data) {
    return "has-description";
},"6":function(depth0,helpers,partials,data) {
    return "disabled";
},"8":function(depth0,helpers,partials,data,blockParams,depths) {
    var stack1, helper, alias1=this.lambda, alias2=this.escapeExpression, alias3=helpers.helperMissing, alias4="function";

  return "				<input type=\"radio\" name=\""
    + alias2(alias1((depths[2] != null ? depths[2].name : depths[2]), depth0))
    + "\" id=\""
    + alias2(alias1((depths[2] != null ? depths[2].name : depths[2]), depth0))
    + "-"
    + alias2(alias1((depth0 != null ? depth0.value : depth0), depth0))
    + "\" value=\""
    + alias2(((helper = (helper = helpers.value || (depth0 != null ? depth0.value : depth0)) != null ? helper : alias3),(typeof helper === alias4 ? helper.call(depth0,{"name":"value","hash":{},"data":data}) : helper)))
    + "\" "
    + ((stack1 = helpers['if'].call(depth0,(depth0 != null ? depth0.selected : depth0),{"name":"if","hash":{},"fn":this.program(9, data, 0, blockParams, depths),"inverse":this.noop,"data":data})) != null ? stack1 : "")
    + " "
    + ((stack1 = helpers['if'].call(depth0,(depth0 != null ? depth0.disabled : depth0),{"name":"if","hash":{},"fn":this.program(6, data, 0, blockParams, depths),"inverse":this.noop,"data":data})) != null ? stack1 : "")
    + " />\n				<label for=\""
    + alias2(alias1((depths[2] != null ? depths[2].name : depths[2]), depth0))
    + "-"
    + alias2(((helper = (helper = helpers.value || (depth0 != null ? depth0.value : depth0)) != null ? helper : alias3),(typeof helper === alias4 ? helper.call(depth0,{"name":"value","hash":{},"data":data}) : helper)))
    + "\" "
    + ((stack1 = helpers['if'].call(depth0,(depth0 != null ? depth0.className : depth0),{"name":"if","hash":{},"fn":this.program(11, data, 0, blockParams, depths),"inverse":this.noop,"data":data})) != null ? stack1 : "")
    + ">\n					"
    + alias2(((helper = (helper = helpers.name || (depth0 != null ? depth0.name : depth0)) != null ? helper : alias3),(typeof helper === alias4 ? helper.call(depth0,{"name":"name","hash":{},"data":data}) : helper)))
    + "\n"
    + ((stack1 = helpers['if'].call(depth0,(depth0 != null ? depth0.description : depth0),{"name":"if","hash":{},"fn":this.program(13, data, 0, blockParams, depths),"inverse":this.noop,"data":data})) != null ? stack1 : "")
    + "				</label>\n";
},"9":function(depth0,helpers,partials,data) {
    return "checked";
},"11":function(depth0,helpers,partials,data) {
    var helper;

  return "class=\""
    + this.escapeExpression(((helper = (helper = helpers.className || (depth0 != null ? depth0.className : depth0)) != null ? helper : helpers.helperMissing),(typeof helper === "function" ? helper.call(depth0,{"name":"className","hash":{},"data":data}) : helper)))
    + "\"";
},"13":function(depth0,helpers,partials,data) {
    var helper;

  return "						<span class=\"description\">"
    + this.escapeExpression(((helper = (helper = helpers.description || (depth0 != null ? depth0.description : depth0)) != null ? helper : helpers.helperMissing),(typeof helper === "function" ? helper.call(depth0,{"name":"description","hash":{},"data":data}) : helper)))
    + "</span>\n";
},"15":function(depth0,helpers,partials,data,blockParams,depths) {
    var stack1, helper, alias1=this.lambda, alias2=this.escapeExpression;

  return "				<div class=\"manual-input\">\n					<input type=\"text\" name=\""
    + alias2(alias1((depths[2] != null ? depths[2].name : depths[2]), depth0))
    + "\" id=\""
    + alias2(alias1((depths[2] != null ? depths[2].name : depths[2]), depth0))
    + "-"
    + alias2(alias1((depth0 != null ? depth0.value : depth0), depth0))
    + "\" value=\""
    + alias2(((helper = (helper = helpers.value || (depth0 != null ? depth0.value : depth0)) != null ? helper : helpers.helperMissing),(typeof helper === "function" ? helper.call(depth0,{"name":"value","hash":{},"data":data}) : helper)))
    + "\" placeholder=\"...\" />\n"
    + ((stack1 = helpers['if'].call(depth0,((stack1 = (depths[2] != null ? depths[2].controller : depths[2])) != null ? stack1.units : stack1),{"name":"if","hash":{},"fn":this.program(16, data, 0, blockParams, depths),"inverse":this.noop,"data":data})) != null ? stack1 : "")
    + "				</div>\n";
},"16":function(depth0,helpers,partials,data,blockParams,depths) {
    var stack1;

  return "						<span>"
    + this.escapeExpression(this.lambda(((stack1 = (depths[3] != null ? depths[3].controller : depths[3])) != null ? stack1.units : stack1), depth0))
    + "</span>\n";
},"18":function(depth0,helpers,partials,data) {
    var stack1, alias1=this.lambda, alias2=this.escapeExpression;

  return "	<div class=\"flex-form__select flex-form__select--horizontal "
    + ((stack1 = helpers['if'].call(depth0,((stack1 = (depth0 != null ? depth0.extra_select : depth0)) != null ? stack1.disabled : stack1),{"name":"if","hash":{},"fn":this.program(6, data, 0),"inverse":this.noop,"data":data})) != null ? stack1 : "")
    + "\">\n		<label for=\""
    + alias2(alias1(((stack1 = (depth0 != null ? depth0.extra_select : depth0)) != null ? stack1.name : stack1), depth0))
    + "\" class=\"title\">"
    + alias2(alias1(((stack1 = (depth0 != null ? depth0.extra_select : depth0)) != null ? stack1.title : stack1), depth0))
    + "</label>\n		<select name=\""
    + alias2(alias1(((stack1 = (depth0 != null ? depth0.extra_select : depth0)) != null ? stack1.name : stack1), depth0))
    + "\" id=\""
    + alias2(alias1(((stack1 = (depth0 != null ? depth0.extra_select : depth0)) != null ? stack1.name : stack1), depth0))
    + "\" "
    + ((stack1 = helpers['if'].call(depth0,((stack1 = (depth0 != null ? depth0.extra_select : depth0)) != null ? stack1.disabled : stack1),{"name":"if","hash":{},"fn":this.program(6, data, 0),"inverse":this.noop,"data":data})) != null ? stack1 : "")
    + ">\n			<option selected disabled>Select</option>\n"
    + ((stack1 = helpers.each.call(depth0,((stack1 = (depth0 != null ? depth0.extra_select : depth0)) != null ? stack1.options : stack1),{"name":"each","hash":{},"fn":this.program(19, data, 0),"inverse":this.noop,"data":data})) != null ? stack1 : "")
    + "		</select>\n		<i class=\"fa fa-chevron-down\"></i>\n	</div>\n";
},"19":function(depth0,helpers,partials,data) {
    var stack1, helper, alias1=helpers.helperMissing, alias2="function", alias3=this.escapeExpression;

  return "				<option value=\""
    + alias3(((helper = (helper = helpers.value || (depth0 != null ? depth0.value : depth0)) != null ? helper : alias1),(typeof helper === alias2 ? helper.call(depth0,{"name":"value","hash":{},"data":data}) : helper)))
    + "\" "
    + ((stack1 = helpers['if'].call(depth0,(depth0 != null ? depth0.selected : depth0),{"name":"if","hash":{},"fn":this.program(20, data, 0),"inverse":this.noop,"data":data})) != null ? stack1 : "")
    + ">"
    + alias3(((helper = (helper = helpers.name || (depth0 != null ? depth0.name : depth0)) != null ? helper : alias1),(typeof helper === alias2 ? helper.call(depth0,{"name":"name","hash":{},"data":data}) : helper)))
    + "</option>\n";
},"20":function(depth0,helpers,partials,data) {
    return "selected";
},"22":function(depth0,helpers,partials,data) {
    var stack1, helper;

  return "	<div class=\"flex-form__select\">\n		<select name=\""
    + this.escapeExpression(((helper = (helper = helpers.name || (depth0 != null ? depth0.name : depth0)) != null ? helper : helpers.helperMissing),(typeof helper === "function" ? helper.call(depth0,{"name":"name","hash":{},"data":data}) : helper)))
    + "-other\">\n			<option disabled selected>Or select one here if yours isn't featured above.</option>\n"
    + ((stack1 = helpers.each.call(depth0,(depth0 != null ? depth0.rest_items : depth0),{"name":"each","hash":{},"fn":this.program(23, data, 0),"inverse":this.noop,"data":data})) != null ? stack1 : "")
    + "		</select>\n		<i class=\"fa fa-chevron-down\"></i>\n	</div>\n";
},"23":function(depth0,helpers,partials,data) {
    var helper, alias1=helpers.helperMissing, alias2="function", alias3=this.escapeExpression;

  return "				<option value=\""
    + alias3(((helper = (helper = helpers.value || (depth0 != null ? depth0.value : depth0)) != null ? helper : alias1),(typeof helper === alias2 ? helper.call(depth0,{"name":"value","hash":{},"data":data}) : helper)))
    + "\">"
    + alias3(((helper = (helper = helpers.name || (depth0 != null ? depth0.name : depth0)) != null ? helper : alias1),(typeof helper === alias2 ? helper.call(depth0,{"name":"name","hash":{},"data":data}) : helper)))
    + "</option>\n";
},"compiler":[6,">= 2.0.0-beta.1"],"main":function(depth0,helpers,partials,data,blockParams,depths) {
    var stack1, helper;

  return "<legend class=\"flex-form__field-title\">"
    + this.escapeExpression(((helper = (helper = helpers.title || (depth0 != null ? depth0.title : depth0)) != null ? helper : helpers.helperMissing),(typeof helper === "function" ? helper.call(depth0,{"name":"title","hash":{},"data":data}) : helper)))
    + " "
    + ((stack1 = helpers['if'].call(depth0,(depth0 != null ? depth0.doc_link : depth0),{"name":"if","hash":{},"fn":this.program(1, data, 0, blockParams, depths),"inverse":this.noop,"data":data})) != null ? stack1 : "")
    + "</legend>\n\n<ul class=\"flex-form__toggle-group\">\n"
    + ((stack1 = helpers.each.call(depth0,(depth0 != null ? depth0.top_items : depth0),{"name":"each","hash":{},"fn":this.program(3, data, 0, blockParams, depths),"inverse":this.noop,"data":data})) != null ? stack1 : "")
    + "</ul>\n\n"
    + ((stack1 = helpers['if'].call(depth0,(depth0 != null ? depth0.extra_select : depth0),{"name":"if","hash":{},"fn":this.program(18, data, 0, blockParams, depths),"inverse":this.noop,"data":data})) != null ? stack1 : "")
    + "\n"
    + ((stack1 = helpers['if'].call(depth0,(depth0 != null ? depth0.rest_items : depth0),{"name":"if","hash":{},"fn":this.program(22, data, 0, blockParams, depths),"inverse":this.noop,"data":data})) != null ? stack1 : "");
},"useData":true,"useDepths":true});
this["HANDLEBARS_TEMPLATES"]["dashboard-table"] = Handlebars.template({"1":function(depth0,helpers,partials,data) {
    var helper, alias1=helpers.helperMissing, alias2="function", alias3=this.escapeExpression;

  return "\n            <tr>\n                <td>"
    + alias3(((helper = (helper = helpers.id || (depth0 != null ? depth0.id : depth0)) != null ? helper : alias1),(typeof helper === alias2 ? helper.call(depth0,{"name":"id","hash":{},"data":data}) : helper)))
    + "</td>\n                <td>"
    + alias3(((helper = (helper = helpers.added_on || (depth0 != null ? depth0.added_on : depth0)) != null ? helper : alias1),(typeof helper === alias2 ? helper.call(depth0,{"name":"added_on","hash":{},"data":data}) : helper)))
    + "</td>\n                <td>"
    + alias3(((helper = (helper = helpers.target || (depth0 != null ? depth0.target : depth0)) != null ? helper : alias1),(typeof helper === alias2 ? helper.call(depth0,{"name":"target","hash":{},"data":data}) : helper)))
    + "</td>\n                <td>"
    + alias3(((helper = (helper = helpers['package'] || (depth0 != null ? depth0['package'] : depth0)) != null ? helper : alias1),(typeof helper === alias2 ? helper.call(depth0,{"name":"package","hash":{},"data":data}) : helper)))
    + "</td>\n                <td><span class=\"badge\">"
    + alias3(((helper = (helper = helpers.score || (depth0 != null ? depth0.score : depth0)) != null ? helper : alias1),(typeof helper === alias2 ? helper.call(depth0,{"name":"score","hash":{},"data":data}) : helper)))
    + " / 10</span></td>\n            </tr>\n\n";
},"3":function(depth0,helpers,partials,data) {
    return "            <tr class=\"less-entries\">\n                <td colspan=\"5\"><span class=\"badge\">No more results</span></td>\n            </tr>\n";
},"compiler":[6,">= 2.0.0-beta.1"],"main":function(depth0,helpers,partials,data) {
    var stack1;

  return "<table class=\"cuckoo-table\">\n\n    <thead>\n        <tr>\n            <th>#</th>\n            <th>Date</th>\n            <th>File</th>\n            <th>Package</th>\n            <th>Score</th>\n        </tr>\n    </thead>\n\n    <tbody>\n\n"
    + ((stack1 = helpers.each.call(depth0,(depth0 != null ? depth0.entries : depth0),{"name":"each","hash":{},"fn":this.program(1, data, 0),"inverse":this.noop,"data":data})) != null ? stack1 : "")
    + "\n"
    + ((stack1 = helpers['if'].call(depth0,(depth0 != null ? depth0.lessEntries : depth0),{"name":"if","hash":{},"fn":this.program(3, data, 0),"inverse":this.noop,"data":data})) != null ? stack1 : "")
    + "\n    </tbody>\n\n</table>";
},"useData":true});
this["HANDLEBARS_TEMPLATES"]["dndupload"] = Handlebars.template({"compiler":[6,">= 2.0.0-beta.1"],"main":function(depth0,helpers,partials,data) {
    var helper;

  return "<div class=\"dndupload__v2\" id=\""
    + this.escapeExpression(((helper = (helper = helpers.uid || (depth0 != null ? depth0.uid : depth0)) != null ? helper : helpers.helperMissing),(typeof helper === "function" ? helper.call(depth0,{"name":"uid","hash":{},"data":data}) : helper)))
    + "\">\n\n    <form id=\"uploader\" action=\"/submit/api/presubmit\" method=\"POST\" enctype=\"multipart/form-data\">\n        <div id=\"container\">\n\n            <input type=\"file\" name=\"files[]\" id=\"file\" class=\"holder_input\" data-multiple-caption=\"{count} files selected\" multiple=\"\">\n            <label for=\"file\" id=\"info\">\n\n                <span class=\"text-idle\">\n                    <strong>Drag your file here or <em>click to select a file.</em></strong>\n                </span>\n\n                <span class=\"text-hovering\">\n                    <strong>Drop your file here.</strong>\n                </span>\n\n                <span class=\"text-dropped\">\n                    <strong>One moment, we're uploading!</strong>\n                    <small>You'll be redirected automatically after we're done.</small>\n                </span>\n\n                <span class=\"text-done\">\n                    <strong>All good!</strong>\n                    <small>One second while we redirect you.</small>\n                </span>\n\n                <span class=\"text-error\">\n                    <strong>Something went wrong!</strong>\n                    <small>The server returned an error. Please check our file compatibility list with the file you're trying to upload or try again.</small>\n                    <small>If the problem persists, send us a feedback report.</small>\n                </span> \n\n            </label>\n\n            <button type=\"submit\" class=\"holder_button\">Upload</button>\n\n            <progress id=\"uploadprogress\" min=\"0\" max=\"100\" value=\"0\">0</progress>\n        </div>\n    </form>\n\n    <div class=\"alternate-progress\"></div>\n    \n</div>\n\n<p id=\"filereader\">File API &amp; FileReader API not supported</p>\n<p id=\"formdata\">XHR2's FormData is not supported</p>\n<p id=\"progress\">XHR2's upload progress isn't supported</p>";
},"useData":true});
this["HANDLEBARS_TEMPLATES"]["dndupload_simple"] = Handlebars.template({"1":function(depth0,helpers,partials,data) {
    var stack1, helper;

  return "        	"
    + ((stack1 = ((helper = (helper = helpers.html || (depth0 != null ? depth0.html : depth0)) != null ? helper : helpers.helperMissing),(typeof helper === "function" ? helper.call(depth0,{"name":"html","hash":{},"data":data}) : helper))) != null ? stack1 : "")
    + "\n";
},"compiler":[6,">= 2.0.0-beta.1"],"main":function(depth0,helpers,partials,data) {
    var stack1, helper, alias1=helpers.helperMissing, alias2="function", alias3=this.escapeExpression;

  return "<div class=\"dndupload__simple\" id=\""
    + alias3(((helper = (helper = helpers.uid || (depth0 != null ? depth0.uid : depth0)) != null ? helper : alias1),(typeof helper === alias2 ? helper.call(depth0,{"name":"uid","hash":{},"data":data}) : helper)))
    + "\">\n	<form id=\"uploader\" action=\""
    + alias3(((helper = (helper = helpers.formAction || (depth0 != null ? depth0.formAction : depth0)) != null ? helper : alias1),(typeof helper === alias2 ? helper.call(depth0,{"name":"formAction","hash":{},"data":data}) : helper)))
    + "\" method=\"post\" enctype=\"multipart/form-data\">\n\n		<input type=\"file\" name=\""
    + alias3(((helper = (helper = helpers.inputName || (depth0 != null ? depth0.inputName : depth0)) != null ? helper : alias1),(typeof helper === alias2 ? helper.call(depth0,{"name":"inputName","hash":{},"data":data}) : helper)))
    + "[]\" id=\"file\" class=\"holder_input\" data-multiple-caption=\"{count} files selected\" multiple=\"\" />\n\n		<h5>"
    + alias3(((helper = (helper = helpers.title || (depth0 != null ? depth0.title : depth0)) != null ? helper : alias1),(typeof helper === alias2 ? helper.call(depth0,{"name":"title","hash":{},"data":data}) : helper)))
    + "</h5>\n		\n"
    + ((stack1 = helpers['if'].call(depth0,(depth0 != null ? depth0.html : depth0),{"name":"if","hash":{},"fn":this.program(1, data, 0),"inverse":this.noop,"data":data})) != null ? stack1 : "")
    + "\n		<progress id=\"uploadprogress\" min=\"0\" max=\"100\" value=\"0\">0</progress>\n	</form>\n</div>";
},"useData":true});
this["HANDLEBARS_TEMPLATES"]["header-table"] = Handlebars.template({"1":function(depth0,helpers,partials,data) {
    var helper;

  return "class=\""
    + this.escapeExpression(((helper = (helper = helpers.className || (depth0 != null ? depth0.className : depth0)) != null ? helper : helpers.helperMissing),(typeof helper === "function" ? helper.call(depth0,{"name":"className","hash":{},"data":data}) : helper)))
    + "\"";
},"3":function(depth0,helpers,partials,data) {
    var helper, alias1=helpers.helperMissing, alias2="function", alias3=this.escapeExpression;

  return "			<tr>\n				<td class=\"key-name\">"
    + alias3(((helper = (helper = helpers.name || (depth0 != null ? depth0.name : depth0)) != null ? helper : alias1),(typeof helper === alias2 ? helper.call(depth0,{"name":"name","hash":{},"data":data}) : helper)))
    + ":</td>\n				<td class=\"key-value\">"
    + alias3(((helper = (helper = helpers.value || (depth0 != null ? depth0.value : depth0)) != null ? helper : alias1),(typeof helper === alias2 ? helper.call(depth0,{"name":"value","hash":{},"data":data}) : helper)))
    + "</td>\n			</tr>\n";
},"compiler":[6,">= 2.0.0-beta.1"],"main":function(depth0,helpers,partials,data) {
    var stack1;

  return "<table "
    + ((stack1 = helpers['if'].call(depth0,(depth0 != null ? depth0.className : depth0),{"name":"if","hash":{},"fn":this.program(1, data, 0),"inverse":this.noop,"data":data})) != null ? stack1 : "")
    + ">\n	<tbody>\n"
    + ((stack1 = helpers.each.call(depth0,(depth0 != null ? depth0.keyv : depth0),{"name":"each","hash":{},"fn":this.program(3, data, 0),"inverse":this.noop,"data":data})) != null ? stack1 : "")
    + "	</tbody>\n</table>";
},"useData":true});
this["HANDLEBARS_TEMPLATES"]["packet-display"] = Handlebars.template({"compiler":[6,">= 2.0.0-beta.1"],"main":function(depth0,helpers,partials,data) {
    var helper, alias1=helpers.helperMissing, alias2="function", alias3=this.escapeExpression;

  return "<div class=\"network-display__request is-open\">\n    <section class=\"network-display__request-details--single\">\n        <div class=\"detail-field\">\n\n            <h4 class=\"detail-field__title flex-distribute\">\n                <span>"
    + alias3(((helper = (helper = helpers.src || (depth0 != null ? depth0.src : depth0)) != null ? helper : alias1),(typeof helper === alias2 ? helper.call(depth0,{"name":"src","hash":{},"data":data}) : helper)))
    + ":"
    + alias3(((helper = (helper = helpers.sport || (depth0 != null ? depth0.sport : depth0)) != null ? helper : alias1),(typeof helper === alias2 ? helper.call(depth0,{"name":"sport","hash":{},"data":data}) : helper)))
    + "</span>\n                <i class=\"fa fa-long-arrow-right\"></i>\n                <span>"
    + alias3(((helper = (helper = helpers.dst || (depth0 != null ? depth0.dst : depth0)) != null ? helper : alias1),(typeof helper === alias2 ? helper.call(depth0,{"name":"dst","hash":{},"data":data}) : helper)))
    + ":"
    + alias3(((helper = (helper = helpers.dport || (depth0 != null ? depth0.dport : depth0)) != null ? helper : alias1),(typeof helper === alias2 ? helper.call(depth0,{"name":"dport","hash":{},"data":data}) : helper)))
    + "</span>\n            </h4>\n\n            <header class=\"detail-field__header with-tabs\">\n                <i class=\"fa fa-file-o\"></i>\n                <div class=\"flex-tabs__tabs\">\n                    <div class=\"flex-tabs__tab tab-output\">\n                        <a href=\"output:plaintext\" class=\"btn btn-sm\">plaintext</a>\n                        <a href=\"output:hex\" class=\"btn btn-sm active\">hex</a>\n                    </div>\n                    <div class=\"flex-tabs__tab tab-mode\">\n                        <a href=\"mode:16\" class=\"btn btn-sm active\">16 bytes</a>\n                        <a href=\"mode:32\" class=\"btn btn-sm\">32 bytes</a>\n                        <a href=\"mode:48\" class=\"btn btn-sm\">48 bytes</a>\n                        <a href=\"mode:64\" class=\"btn btn-sm\">64 bytes</a>\n                    </div>\n                </div>\n            </header>\n\n            <section class=\"detail-field__body\"><pre data-draw=\"source\"></pre></section>\n\n        </div>\n    </section>\n</div>";
},"useData":true});
this["HANDLEBARS_TEMPLATES"]["submission-file-detail"] = Handlebars.template({"1":function(depth0,helpers,partials,data) {
    return "checked";
},"3":function(depth0,helpers,partials,data) {
    var stack1;

  return "			"
    + this.escapeExpression(this.lambda(((stack1 = (depth0 != null ? depth0.item : depth0)) != null ? stack1.fname_short : stack1), depth0))
    + "\n";
},"5":function(depth0,helpers,partials,data) {
    var stack1;

  return "			"
    + this.escapeExpression(this.lambda(((stack1 = (depth0 != null ? depth0.item : depth0)) != null ? stack1.filename : stack1), depth0))
    + "\n";
},"7":function(depth0,helpers,partials,data) {
    var stack1;

  return "			"
    + this.escapeExpression(this.lambda(((stack1 = (depth0 != null ? depth0.item : depth0)) != null ? stack1.rpath_short : stack1), depth0))
    + "\n";
},"9":function(depth0,helpers,partials,data) {
    var stack1;

  return "			"
    + this.escapeExpression(this.lambda(((stack1 = (depth0 != null ? depth0.item : depth0)) != null ? stack1.relapath : stack1), depth0))
    + "\n";
},"11":function(depth0,helpers,partials,data) {
    return "		<li class=\"warning\">\n			<strong>duplicate</strong>\n			This is a duplicate of another submitted file.\n		</li>\n";
},"compiler":[6,">= 2.0.0-beta.1"],"main":function(depth0,helpers,partials,data) {
    var stack1, alias1=this.lambda, alias2=this.escapeExpression;

  return "<header class=\"flex-form__header\">\n	<h4>\n		<label class=\"custom-checkbox\" for=\"file-selected\">\n			<input type=\"checkbox\" id=\"file-selected\" "
    + ((stack1 = helpers['if'].call(depth0,((stack1 = (depth0 != null ? depth0.item : depth0)) != null ? stack1.selected : stack1),{"name":"if","hash":{},"fn":this.program(1, data, 0),"inverse":this.noop,"data":data})) != null ? stack1 : "")
    + " />\n			<span></span>\n		</label>\n\n		<i class=\"fa fa-file-o\"></i> \n"
    + ((stack1 = helpers['if'].call(depth0,((stack1 = (depth0 != null ? depth0.item : depth0)) != null ? stack1.fname_short : stack1),{"name":"if","hash":{},"fn":this.program(3, data, 0),"inverse":this.program(5, data, 0),"data":data})) != null ? stack1 : "")
    + "	</h4>\n</header>\n\n<ul class=\"flex-static__summary\">\n	<li>\n		<strong>path</strong>\n"
    + ((stack1 = helpers['if'].call(depth0,((stack1 = (depth0 != null ? depth0.item : depth0)) != null ? stack1.rpath_short : stack1),{"name":"if","hash":{},"fn":this.program(7, data, 0),"inverse":this.program(9, data, 0),"data":data})) != null ? stack1 : "")
    + "	</li>\n	<li>\n		<strong>type</strong>\n		"
    + alias2(alias1(((stack1 = ((stack1 = (depth0 != null ? depth0.item : depth0)) != null ? stack1.finger : stack1)) != null ? stack1.magic_human : stack1), depth0))
    + "\n	</li>\n	<li>\n		<strong>mime</strong>\n		"
    + alias2(alias1(((stack1 = ((stack1 = (depth0 != null ? depth0.item : depth0)) != null ? stack1.finger : stack1)) != null ? stack1.mime_human : stack1), depth0))
    + "\n	</li>\n	<li>\n		<strong>size</strong>\n		"
    + ((stack1 = (helpers.file_size || (depth0 && depth0.file_size) || helpers.helperMissing).call(depth0,((stack1 = (depth0 != null ? depth0.item : depth0)) != null ? stack1.size : stack1),{"name":"file_size","hash":{},"data":data})) != null ? stack1 : "")
    + "\n	</li>\n"
    + ((stack1 = helpers['if'].call(depth0,((stack1 = (depth0 != null ? depth0.item : depth0)) != null ? stack1.duplicate : stack1),{"name":"if","hash":{},"fn":this.program(11, data, 0),"inverse":this.noop,"data":data})) != null ? stack1 : "")
    + "</ul>\n\n<header class=\"flex-form__header\">\n	<h4><i class=\"fa fa-tasks\"></i> Analysis Specific options</h4>\n	<small>Options you change here are persisted to this file only.</small>\n</header>\n\n<div class=\"per-file-options flex-form\"></div>";
},"useData":true});
this["HANDLEBARS_TEMPLATES"]["submission-selection-list"] = Handlebars.template({"1":function(depth0,helpers,partials,data) {
    var stack1;

  return "					<span class=\"extension-select\">\n						<select class=\"none-selected\">\n							<option disabled selected>Extension</option>\n"
    + ((stack1 = helpers.each.call(depth0,(depth0 != null ? depth0.extensions : depth0),{"name":"each","hash":{},"fn":this.program(2, data, 0),"inverse":this.noop,"data":data})) != null ? stack1 : "")
    + "						</select>\n					</span>\n";
},"2":function(depth0,helpers,partials,data) {
    var alias1=this.lambda, alias2=this.escapeExpression;

  return "								<option value=\""
    + alias2(alias1(depth0, depth0))
    + "\">"
    + alias2(alias1(depth0, depth0))
    + "</option>\n";
},"4":function(depth0,helpers,partials,data) {
    var stack1, alias1=this.lambda, alias2=this.escapeExpression;

  return "			<li data-index=\""
    + alias2(alias1(((stack1 = (depth0 != null ? depth0.filetree : depth0)) != null ? stack1.index : stack1), depth0))
    + "\">\n				<a href=\""
    + alias2(alias1(((stack1 = (depth0 != null ? depth0.filetree : depth0)) != null ? stack1.index : stack1), depth0))
    + "\" "
    + ((stack1 = helpers['if'].call(depth0,((stack1 = (depth0 != null ? depth0.filetree : depth0)) != null ? stack1.is_directory : stack1),{"name":"if","hash":{},"fn":this.program(5, data, 0),"inverse":this.noop,"data":data})) != null ? stack1 : "")
    + ">\n					<strong>\n"
    + ((stack1 = helpers['if'].call(depth0,((stack1 = (depth0 != null ? depth0.filetree : depth0)) != null ? stack1.is_directory : stack1),{"name":"if","hash":{},"fn":this.program(7, data, 0),"inverse":this.program(9, data, 0),"data":data})) != null ? stack1 : "")
    + ((stack1 = helpers['if'].call(depth0,(depth0 != null ? depth0.fname_short : depth0),{"name":"if","hash":{},"fn":this.program(11, data, 0),"inverse":this.program(13, data, 0),"data":data})) != null ? stack1 : "")
    + "					</strong>\n"
    + ((stack1 = helpers.unless.call(depth0,((stack1 = (depth0 != null ? depth0.filetree : depth0)) != null ? stack1.is_directory : stack1),{"name":"unless","hash":{},"fn":this.program(15, data, 0),"inverse":this.noop,"data":data})) != null ? stack1 : "")
    + "				</a>\n			</li>\n";
},"5":function(depth0,helpers,partials,data) {
    return " class=\"disabled\" disabled";
},"7":function(depth0,helpers,partials,data) {
    return "							<i class=\"fa fa-folder-o\"></i>\n";
},"9":function(depth0,helpers,partials,data) {
    return "							<i class=\"fa fa-file-o\"></i>\n";
},"11":function(depth0,helpers,partials,data) {
    return "							"
    + this.escapeExpression(this.lambda((depth0 != null ? depth0.fname_short : depth0), depth0))
    + "\n";
},"13":function(depth0,helpers,partials,data) {
    return "							"
    + this.escapeExpression(this.lambda((depth0 != null ? depth0.filename : depth0), depth0))
    + "\n";
},"15":function(depth0,helpers,partials,data) {
    var stack1;

  return "						<small>\n"
    + ((stack1 = helpers['if'].call(depth0,(depth0 != null ? depth0.rpath_short : depth0),{"name":"if","hash":{},"fn":this.program(16, data, 0),"inverse":this.program(18, data, 0),"data":data})) != null ? stack1 : "")
    + "						</small>\n";
},"16":function(depth0,helpers,partials,data) {
    return "								"
    + this.escapeExpression(this.lambda((depth0 != null ? depth0.rpath_short : depth0), depth0))
    + "\n";
},"18":function(depth0,helpers,partials,data) {
    return "								"
    + this.escapeExpression(this.lambda((depth0 != null ? depth0.relapath : depth0), depth0))
    + "\n";
},"20":function(depth0,helpers,partials,data) {
    return "		<p class=\"description\">These files you selected will be included in your analysis. When ready, click 'analyze' next to the page title.</p>\n";
},"22":function(depth0,helpers,partials,data) {
    return "		<p class=\"description\">You have to select some files before you can analyze. To select, mark the checkboxes before the file/directory names.</p>\n";
},"compiler":[6,">= 2.0.0-beta.1"],"main":function(depth0,helpers,partials,data) {
    var stack1;

  return "<div class=\"flex-form\">\n\n	<header class=\"flex-form__header\">\n		<h4><i class=\"fa fa-list\"></i> Selection</h4>\n	</header>\n\n	<ul class=\"flex-static__summary\" id=\"selection-overview\">\n\n		<li>\n			<div class=\"flex-form__simple-inline no-icon\">\n				<label for=\"search-selection\"><i class=\"fa fa-search\"></i></label>\n				<input type=\"text\" name=\"search-selection\" id=\"search-selection\" placeholder=\"Search selection\" />\n\n"
    + ((stack1 = helpers['if'].call(depth0,(depth0 != null ? depth0.extensions : depth0),{"name":"if","hash":{},"fn":this.program(1, data, 0),"inverse":this.noop,"data":data})) != null ? stack1 : "")
    + "\n			</div>\n		</li>\n\n"
    + ((stack1 = helpers.each.call(depth0,(depth0 != null ? depth0.selection : depth0),{"name":"each","hash":{},"fn":this.program(4, data, 0),"inverse":this.noop,"data":data})) != null ? stack1 : "")
    + "\n		<li class=\"no-results hidden\">\n			<p class=\"description\">Your search returned 0 results</p>\n		</li>\n\n	</ul>\n\n"
    + ((stack1 = helpers.unless.call(depth0,(depth0 != null ? depth0.empty : depth0),{"name":"unless","hash":{},"fn":this.program(20, data, 0),"inverse":this.program(22, data, 0),"data":data})) != null ? stack1 : "")
    + "\n</div>";
},"useData":true});
this["HANDLEBARS_TEMPLATES"]["submission-task-table-body"] = Handlebars.template({"1":function(depth0,helpers,partials,data) {
    var stack1, helper, alias1=helpers.helperMissing, alias2="function", alias3=this.escapeExpression;

  return "	<tr data-task-id=\""
    + alias3(((helper = (helper = helpers.id || (depth0 != null ? depth0.id : depth0)) != null ? helper : alias1),(typeof helper === alias2 ? helper.call(depth0,{"name":"id","hash":{},"data":data}) : helper)))
    + "\" class=\""
    + ((stack1 = helpers['if'].call(depth0,(depth0 != null ? depth0.is_ready : depth0),{"name":"if","hash":{},"fn":this.program(2, data, 0),"inverse":this.noop,"data":data})) != null ? stack1 : "")
    + "\">\n		<td>"
    + alias3(((helper = (helper = helpers.id || (depth0 != null ? depth0.id : depth0)) != null ? helper : alias1),(typeof helper === alias2 ? helper.call(depth0,{"name":"id","hash":{},"data":data}) : helper)))
    + "</td>\n		<td>\n			<i class=\"fa fa-calendar-o\"></i> "
    + alias3(((helper = (helper = helpers.date_added || (depth0 != null ? depth0.date_added : depth0)) != null ? helper : alias1),(typeof helper === alias2 ? helper.call(depth0,{"name":"date_added","hash":{},"data":data}) : helper)))
    + "\n			<i class=\"fa fa-clock-o\"></i> "
    + alias3(((helper = (helper = helpers.time_added || (depth0 != null ? depth0.time_added : depth0)) != null ? helper : alias1),(typeof helper === alias2 ? helper.call(depth0,{"name":"time_added","hash":{},"data":data}) : helper)))
    + "\n		</td>\n		<td>"
    + alias3(((helper = (helper = helpers.target || (depth0 != null ? depth0.target : depth0)) != null ? helper : alias1),(typeof helper === alias2 ? helper.call(depth0,{"name":"target","hash":{},"data":data}) : helper)))
    + "</td>\n		<td>"
    + alias3(((helper = (helper = helpers['package'] || (depth0 != null ? depth0['package'] : depth0)) != null ? helper : alias1),(typeof helper === alias2 ? helper.call(depth0,{"name":"package","hash":{},"data":data}) : helper)))
    + "</td>\n		<td><span class=\"status status-"
    + alias3(((helper = (helper = helpers.status || (depth0 != null ? depth0.status : depth0)) != null ? helper : alias1),(typeof helper === alias2 ? helper.call(depth0,{"name":"status","hash":{},"data":data}) : helper)))
    + "\"></span> "
    + alias3(((helper = (helper = helpers.status || (depth0 != null ? depth0.status : depth0)) != null ? helper : alias1),(typeof helper === alias2 ? helper.call(depth0,{"name":"status","hash":{},"data":data}) : helper)))
    + "</td>\n	</tr>\n";
},"2":function(depth0,helpers,partials,data) {
    return "clickable finished";
},"compiler":[6,">= 2.0.0-beta.1"],"main":function(depth0,helpers,partials,data) {
    var stack1;

  return ((stack1 = helpers.each.call(depth0,(depth0 != null ? depth0.tasks : depth0),{"name":"each","hash":{},"fn":this.program(1, data, 0),"inverse":this.noop,"data":data})) != null ? stack1 : "");
},"useData":true});