/*
 * Copyright (C) 2010-2013 Claudio Guarnieri.
 * Copyright (C) 2014-2016 Cuckoo Foundation.
 * This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
 * See the file 'docs/LICENSE' for copying permission.
 *
 */

$(document).ready(function() {
    $("[data-toggle=popover]").popover();
});

function alertbox(msg, context, attr_id){
    if(context) { context = `alert-${context}`; }
    if(attr_id) { attr_id = `id="${attr_id}"`; }
    return `<div ${attr_id} class="alert ${context} signature">${msg}</div>`;
}

function api_post(url, params, callback, errback, beforesend){
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
        console.log(`ajax post error: ${err}`);

        if(errback) {
            errback(err);
        }
    });
}

String.prototype.capitalize = function() {
    return this.charAt(0).toUpperCase() + this.slice(1);
};
