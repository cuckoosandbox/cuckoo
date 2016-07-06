class Recent {
    constructor() {
        this.loading = false;
        this.limit = 2;
        this.offset = 0;

        this.params = {
            'cats': [],
            'packs': [],
            'score': ''
        };
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

    gather_params(){
        function is_active(data_filter) {
            return $(`div.nav_container>div a[data-filter=${data_filter}]`).parent().hasClass('active');
        }

        if(is_active('cat_files')) this.params['cats'].push('files');
        if(is_active('cat_urls')) this.params['cats'].push('urls');

        if(is_active('score_0-4')) {
            this.params['score'] = '0-4';
        } else if (is_active('score_4-7')) {
            this.params['score'] = '4-7';
        } else if (is_active('score_7-10')) {
            this.params['score'] = '7-10';
        }

        if(is_active('pack_pdf')) this.params['packs'].push('pdf');
        if(is_active('pack_office')) this.params['packs'].push('office');

        return this.params
    }

    /**
     * Contacts API
     * @param {Object} [params] - filters
     * @param {Function} callback - the callback function
     * @return
     */
    get_tasks(){
        let params = this.gather_params();
        params['offset'] = this.offset;
        params['limit'] = this.limit;

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
                html += `<a href="${analysis.id}/summary"><span class="mono">${analysis.completed_on}</span></a>`;
            } else {
                html += `<span class="muted">${analysis.added_on} (added on)</span>`;
            }

            html += '</td><td>';

            if(analysis.status == "reported" || analysis.status == "failed_analysis") {
                html += `<a href="${analysis.id}/summary">${analysis.filename}</a>`;
            } else {
                html += analysis.filename;
            }

            html += '</td><td>';

            if(analysis.status == "reported" || analysis.status == "failed_analysis") {
                html += `<a href="${analysis.id}/summary"><span class="mono">${analysis.sample.md5}</span></a>`;
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