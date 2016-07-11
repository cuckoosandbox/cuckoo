function export_estimate_size(task_id, target_div){
    var params = {
        'task_id': task_id
    };

    $.ajax({  // @TO-DO: Use global ajax call function
        type: 'post',
        contentType: 'application/json',
        url: `/analysis/api/export_estimate_size/`,
        dataType: 'json',
        data: JSON.stringify(params),
        timeout: 40000,
        success: function (data) {
            var size = data['size'];
            var size_human = data['size_human'];

            $(target_div).append('(' + size_human + ')');
        }
    }).fail(function(err){console.log(err)});
}
