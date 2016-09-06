function export_estimate_size(task_id, taken_dirs, taken_files, target_div, prefix){
    var params = {
        "task_id": task_id,
        "dirs": taken_dirs,
        "files": taken_files
    };

    api_post("/analysis/api/export_estimate_size/", params, function(data){
        var size = data["size"];
        var size_human = data["size_human"];
        $(target_div).html(prefix + size_human);
    });
}

function export_get_files(task_id, callback){
    var params = {
        "task_id": task_id
    };

    api_post("/analysis/api/export_get_files/", params, function(data){
        callback(data);
    });
}
