/*
 * Copyright (C) 2010-2013 Claudio Guarnieri.
 * Copyright (C) 2014-2016 Cuckoo Foundation.
 * This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
 * See the file 'docs/LICENSE' for copying permission.
 *
 */

function export_estimate_size(task_id, taken_dirs, taken_files, target_div, prefix){

    if(!task_id) return;

    var params = {
        "task_id": task_id,
        "dirs": taken_dirs,
        "files": taken_files
    };

    CuckooWeb.api_post("/analysis/api/task/export_estimate_size/", params, function(data){
        var size = data["size"];
        var size_human = data["size_human"];
        $(target_div).html(prefix + size_human);
    });
}

function export_get_files(task_id, callback){

    if(!task_id) return;

    var params = {
        "task_id": task_id
    };

    CuckooWeb.api_post("/analysis/api/task/export_get_files/", params, function(data){
        callback(data);
    });
}
