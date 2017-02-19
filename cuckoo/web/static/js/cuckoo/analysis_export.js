"use strict";function export_estimate_size(i,t,s,e,a){if(i){var o={task_id:i,dirs:t,files:s};CuckooWeb.api_post("/analysis/api/task/export_estimate_size/",o,function(i){var t=(i.size,i.size_human);$(e).html(a+t)})}}function export_get_files(i,t){if(i){var s={task_id:i};CuckooWeb.api_post("/analysis/api/task/export_get_files/",s,function(i){t(i)})}}
//# sourceMappingURL=analysis_export.js.map
