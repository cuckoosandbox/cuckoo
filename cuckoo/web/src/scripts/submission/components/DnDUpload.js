/*
 * Copyright (C) 2010-2013 Claudio Guarnieri.
 * Copyright (C) 2014-2016 Cuckoo Foundation.
 * This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
 * See the file 'docs/LICENSE' for copying permission.
 *
 */

/**
 * An abstract HTML widget for file uploads.
 *
 * Supports:
 *   - Multiple files
 *   - Drag & Drop OR file dialog
 *   - Progress bar
 *   - Minimum size on screen: 300x230
 *
 *   Required parameter `target` takes a CSS selector inside which
 *   the necessary HTML is spawned. Multiple of these widgets can exist on
 *   one page due to OOP.
 */

var debugging = false;

const DEFAULT_UPLOADER_CONFIG = {
    target: null,
    endpoint: null,
    template: null,
    ajax: true,
    templateData: {},
    dragstart: function() {},
    dragend: function() {},
    drop: function() {},
    error: function() {},
    success: function() {},
    progress: function() {},
    change: function() {}
}

class Uploader {

    constructor(options) {

        let _self = this;
        
        this.options = $.extend({

            target: null,
            endpoint: null,
            template: null,
            ajax: true,
            templateData: {},
            dragstart: function() {},
            dragend: function() {},
            drop: function() {},
            error: function() {},
            success: function() {},
            progress: function() {},
            change: function() {}

        }, options);

        this.endpoint = this.options.endpoint;
        this._success_callback = this.options.success;
        this._progress_callback = this.options.progress;

        this._dragstart_callback = this.options.dragstart;
        this._dragend_callback = this.options.dragend;
        this._drop_callback = this.options.drop;
        this._error_callback = this.options.error;
        this._change_callback = this.options.change;

        this._selectors = {
            "uid": `dndupload_${Uploader.generateUUID()}`,
            "target": _self.options.target
        };

        this.html = null;

        this._usesTemplate = false;
        this._bound = false;
    }

    /**
     * Clears `target`, appends HTML and binds events (if necessary)
     * @return
     */
    draw(){

        $(this._selectors["target"]).empty();

        var html = `
            <div class="dndupload" id="${this._selectors["uid"]}">
                <form id="uploader" action="/submit/api/presubmit" method="POST" enctype="multipart/form-data">
                    <div id="container">
                        <svg xmlns="http://www.w3.org/2000/svg" width="50" height="43" viewBox="0 0 50 43">
                            <path d="M48.4 26.5c-.9 0-1.7.7-1.7 1.7v11.6h-43.3v-11.6c0-.9-.7-1.7-1.7-1.7s-1.7.7-1.7 1.7v13.2c0 .9.7 1.7 1.7 1.7h46.7c.9 0 1.7-.7 1.7-1.7v-13.2c0-1-.7-1.7-1.7-1.7zm-24.5 6.1c.3.3.8.5 1.2.5.4 0 .9-.2 1.2-.5l10-11.6c.7-.7.7-1.7 0-2.4s-1.7-.7-2.4 0l-7.1 8.3v-25.3c0-.9-.7-1.7-1.7-1.7s-1.7.7-1.7 1.7v25.3l-7.1-8.3c-.7-.7-1.7-.7-2.4 0s-.7 1.7 0 2.4l10 11.6z"/>
                        </svg>
    
                        <input type="file" name="files[]" id="file" class="holder_input" data-multiple-caption="{count} files selected" multiple="">
                        <label for="file" id="info">
                            <strong>Choose files</strong>
                            <span class="box__dragndrop"> or drag them here</span>.
                        </label>
    
                        <button type="submit" class="holder_button">Upload</button>
    
                        <progress id="uploadprogress" min="0" max="100" value="0">0</progress>
                    </div>
                </form>
            </div>
        `;

        if(this.options.template) {
            this._usesTemplate = true;

            this.options.templateData.uid = this._selectors["uid"];

            if(!this.options.templateData['inputName']) {
                this.options.templateData.inputName = 'files';
            }

            var html = this.options.template(this.options.templateData);
        }

        $(this._selectors["target"]).append(html);
        if(!this._bound) this._bind();
    }

    /**
     * Builds references to form elements and creates events.
     * @return
     */
    _bind(){
        let _self = this;
        let holder = document.querySelector(`div#${_self._selectors["uid"]}`);

        // save references to the HTML tags that belong exclusively to this widget in
        // _self._selectors to avoid global namespace pollution.
        _self._selectors["holder"] = holder;
        _self._selectors["progress"] = document.querySelector(_self._selectors["target"])
                                               .querySelector("progress#uploadprogress");

        _self._selectors["upload"] = holder.querySelector("upload");
        _self._selectors["form"] = holder.querySelector("form#uploader");

        // test the current browser capabilities
        _self._selectors["tests"] = {
            filereader: typeof FileReader != "undefined",
            dnd: "draggable" in document.createElement("span"),
            formdata: !!window.FormData,
            progress: "upload" in new XMLHttpRequest
        };

        // keeping track of informative HTML tags
        _self._selectors["support"] = {
            filereader: document.getElementById("filereader"),
            formdata: document.getElementById("formdata"),
            progress: document.getElementById("progress")
        };

        "filereader formdata progress".split(" ").forEach(function(api){

            if (_self._selectors["tests"][api] === false) {
                if(!_self._selectors["support"][api]) return;
                _self._selectors["support"][api].className = "fail";
            } else {
                if(!_self._selectors["support"][api]) return;
                _self._selectors["support"][api].className = "hidden";
            }

        });

        // listen for changes on the input tag. If a user choose a file manually; fire the
        // form submit programmatically

        _self._selectors["holder"].querySelector('input[type="file"]').addEventListener("change", function(e){

            // console.log(_self);
            // return;

            if(_self.options.ajax) {

                var event = document.createEvent("HTMLEvents");
                event.initEvent("submit", true, true);
                _self._selectors["form"].dispatchEvent( event );
                _self._change_callback(_self, holder);

            } else {

                $(_self._selectors["form"]).submit();

            }
            
        });

        // do our own thing when the form is submitted

        $(_self._selectors["form"]).bind('submit', function(event){

            if(_self.options.ajax) {
                event.preventDefault();
                this._process_files();
            }

        }.bind(this));

        // test for drag&drop
        if (_self._selectors["tests"].dnd){
            // change appearance while drag&dropping
            holder.querySelector("form#uploader").ondragover = function(){
                this.className = "hover";
                _self._dragstart_callback(_self, holder);
                return false;
            };

            holder.querySelector("form#uploader").ondragend = function(){
                this.className = "";
                return false;
            };

            // holder.querySelector("form#uploader").ondragstart = function() {
            //     console.log('drag start');
            // }

            ["dragleave", "dragend", "drop"].forEach(function(event){
                holder.querySelector("form#uploader").addEventListener(event, function(){
                    //form.classList.remove( "is-dragover" );
                    this.classList.remove("hover");
                    _self._dragend_callback(_self, holder);
                });
            });

            // process the files on drop
            holder.querySelector("form#uploader").ondrop = function(e){
                this.className = "";

                if(_self.options.ajax) {

                    e.preventDefault();
                    var dropCallbackOutput = _self._drop_callback(_self, holder);

                    // if this callback returns 'false', don't process the file directly. This 
                    // controls auto-uploading from the configuration. Developer can now
                    // embed an upload-trigger himself, if wanted.
                    if(dropCallbackOutput === false)
                        return;

                    _self._process_files(e.dataTransfer.files);

                } else {

                    if(e.dataTransfer.files) {
                        _self._selectors["holder"].querySelector('input[type="file"]').files = e.dataTransfer.files;
                    }

                }

            };
        } else {

            this._selectors["upload"].className = "hidden";
            this._selectors["upload"].querySelector("input").onchange = function(){

                if(_self.options.ajax) {
                    _self._process_files(this.files);
                }

            };
        }

        this._bound = true;
    }

    /**
     * Reads the files and creates FormData
     * @return
     */
    _process_files(files) {

        if(debugging) return;

        let _self = this;
        let formdata = new FormData();

        if(_self._selectors["holder"].querySelector('input[type="file"]').files && !files){
            formdata = new FormData(_self._selectors["form"]);
        } else {

            for(var i = 0; i < files.length; i++){
                formdata.append("files[]", files[i]);
            }
        }

        if(formdata){
            this._upload(formdata);
        }
    }

    /**
     * Sends FormData to the endpoint
     * @return
     */
    _upload(formdata){
        let _self = this;
        let xhr = new XMLHttpRequest();

        formdata["type"] = "files";

        xhr.open('POST', this.endpoint);
        xhr.setRequestHeader('X-CSRFToken', CuckooWeb.csrf_token());

        // update progress bar when server response is received
        xhr.onload = function(){
            _self._selectors["progress"].value = _self._selectors["progress"].innerHTML = 100;

            // fire a callback passing along the progress status
            if(_self._progress_callback) {
                _self._progress_callback.bind(_self, 100, document.querySelector(`div#${_self._selectors["uid"]}`))();
            }
        };

        xhr.onreadystatechange = function(){
            if(xhr.readyState === 4) {

                if(xhr.status == 200) {

                    // _self.display_text("Done");

                    setTimeout(function() {
                        _self._success_callback(xhr, document.querySelector(`div#${_self._selectors["uid"]}`));
                    }, 600);

                } else if(xhr.status == 0) {

                } else {
                    // _self.display_text(`Error: http.status = ${xhr.status} OR response.status not OK`);
                    _self._error_callback(_self, document.querySelector(`div#${_self._selectors["uid"]}`));
                }
            }
        };

        // update progress bar while uploading
        if(this._selectors["tests"].progress){
            xhr.upload.onprogress = function(event){
                if(event.lengthComputable){
                    let complete = (event.loaded / event.total*100 | 0);
                    _self._selectors["progress"].value = _self._selectors["progress"].innerHTML = complete;

                    // fire a callback passing along the progress status
                    if(_self._progress_callback) {
                        _self._progress_callback.bind(_self, 100, document.querySelector(`div#${_self._selectors["uid"]}`))();
                    }
                }
            }
        }

        xhr.send(formdata);
    }

    /**
     * Generates UUID
     * @return
     */
    static generateUUID(){
        return (new Date).getTime();
    }
}

export { Uploader, DEFAULT_UPLOADER_CONFIG };
