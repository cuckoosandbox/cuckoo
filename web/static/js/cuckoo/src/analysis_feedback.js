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

    api_post("/analysis/api/feedback_send/", params, function(data){
        callback(data);
    });
}
