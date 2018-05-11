"use strict";

/*
 * Copyright (C) 2010-2013 Claudio Guarnieri.
 * Copyright (C) 2014-2016 Cuckoo Foundation.
 * This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
 * See the file 'docs/LICENSE' for copying permission.
 *
 */

function misp_export(task_id, target_div) {

    if (!task_id) return;

    var params = {
        "task_id": task_id
    };

    CuckooWeb.api_post("/analysis/api/task/misp_export/", params, function (data) {
        callback(data);
    });
}