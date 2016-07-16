function feedback_send(task_id, email, message, include_analysis, include_memdump, callback){
    var params = {
        "task_id": task_id,
        "email": email,
        "message": message,
        "include_memdump": include_memdump,
        "include_analysis": include_analysis
    };

    $.ajax({
        type: "post",
        contentType: "application/json",
        url: `/analysis/api/feedback_send/`,
        dataType: "json",
        data: JSON.stringify(params),
        timeout: 40000,
        success: function (data) {
            callback(data);
        }
    }).fail(function(err){console.log(err)});
}
