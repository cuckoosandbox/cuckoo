class Recent {
    constructor() {
        this.loading = false;
    }

    toggle_loading(){
        if(this.loading){
            console.log("loading");
            this.loading = true;
        } else {
            console.log("loadingg");
            this.loading = false;
        }
    }

    /**
     * Contacts API
     * @param {Object} [params] - filters
     * @param {Function} callback - the callback function
     * @return
     */
    recent(params){
        let self = this;

        $.ajax({
            type: 'post',
            contentType: 'application/json',
            url: `api/recent/`,
            dataType: 'json',
            data: JSON.stringify(params),
            timeout: 40000,
            beforeSend: function(){
                self.toggle_loading(self);
            },
            success: function(data){
                self.cb(data);
            }
        }).fail(err => console.log(err))
    }

    cb(data) {
        data.forEach(function(analysis, i){
            let html = '<tr><td>';

            if(analysis.status == "reported" || analysis.status == "failed_analysis") {
                html += `<a href="#"><span class="mono">${analysis.completed_on}</span></a>`;
            } else {
                html += `<span class="muted">${analysis.added_on} (added on)</span>`;
            }

            html += '</td><td>';

            if(analysis.status == "reported" || analysis.status == "failed_analysis") {
                html += `<a href="#">${analysis.filename}</a>`;
            } else {
                html += analysis.filename;
            }

            html += '</td><td>';

            if(analysis.status == "reported" || analysis.status == "failed_analysis") {
                html += `<a href="#"><span class="mono">${analysis.sample.md5}</span></a>`;
            } else {
                html += `<span class="mono">${analysis.sample.md5}</span>`;
            }

            html += '</td><td>';

            if (analysis.status == "pending"){
                html += '<span class="text-muted">pending</span>';
            } else if(analysis.status == "running") {
                html += '<span class="text-warning">running</span>';
            } else if(analysis.status == "completed") {
                html += '<span class="text-info">completed</span>';
            } else if(analysis.status == "reported") {
                if(analysis.errors) {
                    html += '<span class="text-danger">';
                } else {
                    html += '<span class="text-success">';
                }

                html += 'reported</span>';
            } else {
                html += `<span class="text-danger">${analysis.status}</span>`;
            }

            html += '</td></tr>';

            $('table#recent tbody').append(html);
        });
    }
}