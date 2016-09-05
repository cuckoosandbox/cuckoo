'use strict';

function export_estimate_size(task_id, taken_dirs, taken_files, target_div, prefix) {
    var params = {
        'task_id': task_id,
        'dirs': taken_dirs,
        'files': taken_files
    };

    $.ajax({
        type: "post",
        contentType: "application/json",
        url: '/analysis/api/export_estimate_size/',
        dataType: "json",
        data: JSON.stringify(params),
        timeout: 40000,
        success: function success(data) {
            var size = data["size"];
            var size_human = data["size_human"];
            $(target_div).html(prefix + size_human);
        }
    }).fail(function (err) {
        console.log(err);
    });
}

function export_get_files(task_id, callback) {
    var params = {
        "task_id": task_id
    };

    $.ajax({ // @TO-DO: Use global ajax call function
        type: "post",
        contentType: "application/json",
        url: '/analysis/api/export_get_files/',
        dataType: "json",
        data: JSON.stringify(params),
        timeout: 40000,
        success: function success(data) {
            callback(data);
        }
    }).fail(function (err) {
        console.log(err);
    });
}

//# sourceMappingURL=analysis_export.js.map