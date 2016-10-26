(function e(t,n,r){function s(o,u){if(!n[o]){if(!t[o]){var a=typeof require=="function"&&require;if(!u&&a)return a(o,!0);if(i)return i(o,!0);var f=new Error("Cannot find module '"+o+"'");throw f.code="MODULE_NOT_FOUND",f}var l=n[o]={exports:{}};t[o][0].call(l.exports,function(e){var n=t[o][1][e];return s(n?n:e)},l,l.exports,e,t,n,r)}return n[o].exports}var i=typeof require=="function"&&require;for(var o=0;o<r.length;o++)s(r[o]);return s})({1:[function(require,module,exports){
"use strict";

/*
 * Copyright (C) 2010-2013 Claudio Guarnieri.
 * Copyright (C) 2014-2016 Cuckoo Foundation.
 * This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
 * See the file 'docs/LICENSE' for copying permission.
 *
 */

function export_estimate_size(task_id, taken_dirs, taken_files, target_div, prefix) {
    var params = {
        "task_id": task_id,
        "dirs": taken_dirs,
        "files": taken_files
    };

    CuckooWeb.api_post("/analysis/api/task/export_estimate_size/", params, function (data) {
        var size = data["size"];
        var size_human = data["size_human"];
        $(target_div).html(prefix + size_human);
    });
}

function export_get_files(task_id, callback) {
    var params = {
        "task_id": task_id
    };

    CuckooWeb.api_post("/analysis/api/task/export_get_files/", params, function (data) {
        callback(data);
    });
}

},{}]},{},[1]);
