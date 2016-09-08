/*
 * Copyright (C) 2010-2013 Claudio Guarnieri.
 * Copyright (C) 2014-2016 Cuckoo Foundation.
 * This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
 * See the file 'docs/LICENSE' for copying permission.
 *
 */

function feedback_send(task_id, firstname, email, company, message, include_analysis, include_memdump, callback){
    var params = {
        "task_id": task_id,
        "email": email,
        "message": message,
        "firstname": firstname,
        "company": company,
        "include_memdump": include_memdump,
        "include_analysis": include_analysis
    };

    CuckooWeb.api_post("/analysis/api/feedback_send/", params, function(data){
        callback(data);
    });
}
