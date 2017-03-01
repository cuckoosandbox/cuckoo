"use strict";

/*
 * Copyright (C) 2010-2013 Claudio Guarnieri.
 * Copyright (C) 2014-2016 Cuckoo Foundation.
 * This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
 * See the file 'docs/LICENSE' for copying permission.
 *
 */

function feedback_send(task_id, name, email, company, message, include_analysis, include_memdump, callback) {
    var params = {
        "task_id": task_id,
        "email": email,
        "message": message,
        "name": name,
        "company": company,
        "include_memdump": include_memdump,
        "include_analysis": include_analysis
    };

    CuckooWeb.api_post("/analysis/api/task/feedback_send/", params, function (data) {
        callback(data);
    }, function (err) {
        if (err.responseJSON.hasOwnProperty("message")) {
            var _message = err.responseJSON.message;
            $("#modal_feedback").find("#result").html(_message);
        }
    });
}
//# sourceMappingURL=analysis_feedback.js.map
