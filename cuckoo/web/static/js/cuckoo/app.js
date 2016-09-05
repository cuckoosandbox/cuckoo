"use strict";

$(document).ready(function () {
    $("[data-toggle=popover]").popover();
});

function alertbox(msg, context, attr_id) {
    if (context) {
        context = "alert-" + context;
    }
    if (attr_id) {
        attr_id = "id=\"" + attr_id + "\"";
    }
    return "<div " + attr_id + " class=\"alert " + context + " signature\">" + msg + "</div>";
}

//# sourceMappingURL=app.js.map