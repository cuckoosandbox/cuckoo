"use strict";function feedback_send(e,s,a,n,i,c,d,m){var o={task_id:e,email:a,message:i,name:s,company:n,include_memdump:d,include_analysis:c};CuckooWeb.api_post("/analysis/api/task/feedback_send/",o,function(e){m(e)},function(e){if(e.responseJSON.hasOwnProperty("message")){var s=e.responseJSON.message;$("#modal_feedback").find("#result").html(s)}})}
//# sourceMappingURL=analysis_feedback.js.map
