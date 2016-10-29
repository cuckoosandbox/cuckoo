/*
 * Copyright (C) 2010-2013 Claudio Guarnieri.
 * Copyright (C) 2014-2016 Cuckoo Foundation.
 * This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
 * See the file 'docs/LICENSE' for copying permission.
 *
 */

/**
 * CuckooWeb miscellaneous functions class.
 */
class CuckooWeb {
    // mpen @ http://stackoverflow.com/a/14919494/2054778
    static human_size(bytes, si){
        var thresh = si ? 1000 : 1024;
        if(Math.abs(bytes) < thresh) {
            return bytes + ' B';
        }
        var units = si
            ? ['kB','MB','GB','TB','PB','EB','ZB','YB']
            : ['KiB','MiB','GiB','TiB','PiB','EiB','ZiB','YiB'];
        var u = -1;
        do {
            bytes /= thresh;
            ++u;
        } while(Math.abs(bytes) >= thresh && u < units.length - 1);
        return bytes.toFixed(1)+' '+units[u];
    }

    static api_post(url, params, callback, errback, beforesend){
        let data = JSON.stringify(params);

        $.ajax({
            type: "post",
            contentType: "application/json",
            url: url,
            dataType: "json",
            data: data,
            timeout: 20000,
            beforeSend: function(){
                if(beforesend){
                    beforesend()
                }
            },
            success: function(data){
                if(callback) {
                    callback(data);
                }
            }
        }).fail(function(err){
            if(err.hasOwnProperty("responseJSON") && err.responseJSON.hasOwnProperty("message")){
                console.log(`POST err: ${err.responseJSON.message}`);
            } else {
                console.log(`POST err: ${err}`);
            }

            if(errback) {
                errback(err);
            }
        });
    }

    static getFormattedDate(jsondate) {
        var date = new Date(jsondate);

        var month = date.getMonth() + 1;
        var day = date.getDate();
        var hour = date.getHours();
        var min = date.getMinutes();
        var sec = date.getSeconds();

        month = (month < 10 ? "0" : "") + month;
        day = (day < 10 ? "0" : "") + day;
        hour = (hour < 10 ? "0" : "") + hour;
        min = (min < 10 ? "0" : "") + min;
        sec = (sec < 10 ? "0" : "") + sec;

        return date.getFullYear() + "-" + month + "-" + day + " " +  hour + ":" + min;
    }

    static redirect(location){
        window.location.href = location;
    }
}

$(document).ready(function() {

    $("[data-toggle=popover]").popover();

    // INTERACTION FOR CUCKOO ERRORS
    $(".cuckoo-errors #errors").on('shown.bs.collapse', function(e) {
        $(".cuckoo-errors [data-toggle='collapse']").text('hide');
    }).on('hidden.bs.collapse', function() {
        $(".cuckoo-errors [data-toggle='collapse']").text('show');
    });

    $(".cuckoo-errors .expand-error").bind('click', function(e) {
        e.preventDefault();

        if($(this).parent().hasClass('expanded')) {
            $(this).attr('title', 'Expand error message');
            $(this).parent().removeClass('expanded');
        } else {
            $(this).attr('title', 'Collapse error message');
            $(this).parent().addClass('expanded');
        }
    });

});

function alertbox(msg, context, attr_id){
    if(context) { context = `alert-${context}`; }
    if(attr_id) { attr_id = `id="${attr_id}"`; }
    return `<div ${attr_id} class="alert ${context} signature">${msg}</div>`;
}

String.prototype.capitalize = function() {
    return this.charAt(0).toUpperCase() + this.slice(1);
};