!function () {
    function e(t, n, o) {
        function i(s, a) {
            if (!n[s]) {
                if (!t[s]) {
                    var c = "function" == typeof require && require;
                    if (!a && c) return c(s, !0);
                    if (r) return r(s, !0);
                    var l = new Error("Cannot find module '" + s + "'");
                    throw l.code = "MODULE_NOT_FOUND", l
                }
                var u = n[s] = {exports: {}};
                t[s][0].call(u.exports, function (e) {
                    var n = t[s][1][e];
                    return i(n || e)
                }, u, u.exports, e, t, n, o)
            }
            return n[s].exports
        }

        for (var r = "function" == typeof require && require, s = 0; s < o.length; s++) i(o[s]);
        return i
    }

    return e
}()({
    1: [function (e, t, n) {
        "use strict";

        function o(e) {
            return e && e.__esModule ? e : {default: e}
        }

        function i(e, t) {
            if (!(e instanceof t)) throw new TypeError("Cannot call a class as a function")
        }

        function r(e, t) {
            if (!e) throw new ReferenceError("this hasn't been initialised - super() hasn't been called");
            return !t || "object" != typeof t && "function" != typeof t ? e : t
        }

        function s(e, t) {
            if ("function" != typeof t && null !== t) throw new TypeError("Super expression must either be null or a function, not " + typeof t);
            e.prototype = Object.create(t && t.prototype, {
                constructor: {
                    value: e,
                    enumerable: !1,
                    writable: !0,
                    configurable: !0
                }
            }), t && (Object.setPrototypeOf ? Object.setPrototypeOf(e, t) : e.__proto__ = t)
        }

        Object.defineProperty(n, "__esModule", {value: !0});
        var a = function () {
            function e(e, t) {
                for (var n = 0; n < t.length; n++) {
                    var o = t[n];
                    o.enumerable = o.enumerable || !1, o.configurable = !0, "value" in o && (o.writable = !0), Object.defineProperty(e, o.key, o)
                }
            }

            return function (t, n, o) {
                return n && e(t.prototype, n), o && e(t, o), t
            }
        }(), c = e("./Hookable"), l = o(c), u = function (e) {
            function t(e) {
                i(this, t);
                var n = r(this, (t.__proto__ || Object.getPrototypeOf(t)).call(this));
                if (n.hooks = {connect: [], error: [], end: []}, !window.Guacamole) {
                    var o;
                    return console.error("No Guacamole! Did you forget to process the avocados in src/scripts/rdp/guac?"), o = !1, r(n, o)
                }
                return n.display = e.display, n.parent = e.client, n.client = null, n._mouse = null, n._keyboard = null, n
            }

            return s(t, e), a(t, [{
                key: "connect", value: function () {
                    let token = Cookies.get("csrftoken");
                    if (!token) {
                        let field = $("input[name=csrfmiddlewaretoken]");
                        if (field && field.val()) {
                            token = field.val();
                        }
                    }
                    if (token) {
                        var t = new Guacamole.HTTPTunnel("tunnel/", false, {"X-CSRFToken": token});
                    } else {
                        console.warn("Request to " + url + " on page without CSRF token");
                        var t = new Guacamole.HTTPTunnel("tunnel/");
                    }
                    var e = this, n = this.client = new Guacamole.Client(t);
                    this.display.html(n.getDisplay().getElement()), t.onerror = n.onerror = function (t) {
                        switch (t.code) {
                            case 523:
                                break;
                            default:
                                e.dispatchHook("error", t)
                        }
                    }, t.onstatechange = function (t) {
                        2 == t && e.dispatchHook("ended")
                    }, n.connect(), this.dispatchHook("connect", n)
                }
            }, {
                key: "mouse", value: function () {
                    var e = this, t = !(arguments.length > 0 && void 0 !== arguments[0]) || arguments[0];
                    if (this.client && t) {
                        this._mouse = new Guacamole.Mouse(this.client.getDisplay().getElement());
                        var n = function (t) {
                            return e.client.sendMouseState(t)
                        };
                        this._mouse.onmousemove = this._mouse.onmouseup = this._mouse.onmousedown = function (t) {
                            e.parent.toolbar.buttons.control.toggled && n(t)
                        }
                    }
                }
            }, {
                key: "keyboard", value: function () {
                    var e = this, t = !(arguments.length > 0 && void 0 !== arguments[0]) || arguments[0];
                    this.client && (t ? (this._keyboard = new Guacamole.Keyboard(document), this._keyboard.onkeydown = function (t) {
                        e.parent.toolbar.buttons.control.toggled && e.client.sendKeyEvent(1, t)
                    }, this._keyboard.onkeyup = function (t) {
                        e.parent.toolbar.buttons.control.toggled && e.client.sendKeyEvent(0, t)
                    }) : this._keyboard = null)
                }
            }, {
                key: "getCanvas", value: function () {
                    return !!this.client && this.client.getDisplay().getDefaultLayer().getCanvas()
                }
            }, {
                key: "checkReady", value: function (e) {
                    var t = arguments.length > 1 && void 0 !== arguments[1] && arguments[1],
                        n = arguments.length > 2 && void 0 !== arguments[2] ? arguments[2] : "completed",
                        o = function () {
                            return new Promise(function (t, o) {
                                try {
                                    $.ajax({
                                        url: "/analysis/api/tasks/info/",
                                        type: "POST",
                                        dataType: "json",
                                        contentType: "application/json; charset=utf-8",
                                        data: JSON.stringify({task_ids: [e]}),
                                        beforeSend: function (request) {
                                            let token = Cookies.get("csrftoken");
                                            if (!token) {
                                                let field = $("input[name=csrfmiddlewaretoken]");
                                                if (field && field.val()) {
                                                    token = field.val();
                                                }
                                            }
                                            if (token) {
                                                request.setRequestHeader("X-CSRFToken", token);
                                            } else {
                                                console.warn("Request to " + url + " on page without CSRF token");
                                            }
                                        },
                                        success: function (o, i) {
                                            if (o.status !== !0) throw"ajax error";
                                            var r = o.data[e];
                                            r.status === n ? t(!0, r) : t(!1, r)
                                        },
                                        error: function (e) {
                                            throw e
                                        }
                                    })
                                } catch (e) {
                                    return o(e)
                                }
                            })
                        };
                    return t === !0 ? new Promise(function (e, t) {
                        var n = setInterval(function () {
                            o().then(function (t) {
                                if (t === !0) return n = clearInterval(n), e(t)
                            }, function (e) {
                                return t(e)
                            })
                        }, 1e3)
                    }).catch(function (e) {
                        return console.log(e)
                    }) : o()
                }
            }]), t
        }(l.default);
        n.default = u
    }, {"./Hookable": 2}], 2: [function (e, t, n) {
        "use strict";

        function o(e, t) {
            if (!(e instanceof t)) throw new TypeError("Cannot call a class as a function")
        }

        Object.defineProperty(n, "__esModule", {value: !0});
        var i = function () {
            function e(e, t) {
                for (var n = 0; n < t.length; n++) {
                    var o = t[n];
                    o.enumerable = o.enumerable || !1, o.configurable = !0, "value" in o && (o.writable = !0), Object.defineProperty(e, o.key, o)
                }
            }

            return function (t, n, o) {
                return n && e(t.prototype, n), o && e(t, o), t
            }
        }(), r = function () {
            return !0
        }, s = function () {
            function e() {
                o(this, e), this.hooks = {}
            }

            return i(e, [{
                key: "on", value: function (e) {
                    var t = arguments.length > 1 && void 0 !== arguments[1] ? arguments[1] : r;
                    return this.hooks[e] || (this.hooks[e] = []), this.hooks[e].push(t), this
                }
            }, {
                key: "dispatchHook", value: function () {
                    var e = this, t = arguments.length > 0 && void 0 !== arguments[0] ? arguments[0] : "",
                        n = arguments.length > 1 && void 0 !== arguments[1] ? arguments[1] : {};
                    return this.hooks[t] && this.hooks[t].forEach(function (t) {
                        t instanceof Function && t.call(e, n)
                    }), this
                }
            }]), e
        }();
        n.default = s
    }, {}], 3: [function (e, t, n) {
        "use strict";

        function o(e) {
            return e && e.__esModule ? e : {default: e}
        }

        function i(e, t) {
            if (!(e instanceof t)) throw new TypeError("Cannot call a class as a function")
        }

        function r(e) {
            var t = !(arguments.length > 1 && void 0 !== arguments[1]) || arguments[1];
            if (!e.length) return !1;
            var n = e.html();
            return t ? $(n) : n
        }

        function s(e) {
            var t = arguments.length > 1 && void 0 !== arguments[1] && arguments[1], n = {};
            for (var o in e) e[o] instanceof Function ? n[o] = e[o].call(t || window) : n[o] = e[o];
            return n
        }

        Object.defineProperty(n, "__esModule", {value: !0}), n.RDPRender = void 0;
        var a = function () {
            function e(e, t) {
                for (var n = 0; n < t.length; n++) {
                    var o = t[n];
                    o.enumerable = o.enumerable || !1, o.configurable = !0, "value" in o && (o.writable = !0), Object.defineProperty(e, o.key, o)
                }
            }

            return function (t, n, o) {
                return n && e(t.prototype, n), o && e(t, o), t
            }
        }(), c = e("./Hookable"), l = (o(c), function () {
            function e(t, n) {
                i(this, e), this.client = t, this.template = r(n), this.active = !1
            }

            return a(e, [{
                key: "render", value: function () {
                    this.template && (this.client.$.find(".rdp-app__viewport").html(this.template), this.active = !0)
                }
            }, {
                key: "destroy", value: function () {
                    this.template.remove()
                }
            }]), e
        }()), u = function e(t) {
            var n = this, o = arguments.length > 1 && void 0 !== arguments[1] ? arguments[1] : {};
            i(this, e), this.parent = t, this.dialog = o, this.interactions = o.interactions || {}, this.model = s(o.model || {});
            var r = this.parent.base.find("form.rdp-dialog__options");
            this.parent.base.find("button").on("click", function (e) {
                var t = $(e.currentTarget).val();
                n.interactions[t] && r.submit(function () {
                    return n.interactions[t](n.parent)
                })
            }), r.bind("submit", function (e) {
                e.preventDefault()
            })
        }, f = function () {
            function e(t) {
                var n = arguments.length > 1 && void 0 !== arguments[1] ? arguments[1] : {};
                i(this, e), this.client = t, this.base = n.el, this.interaction = null, this.activeModel = null, this.dialogs = n.dialogs || {}, this.isOpen = this.base.prop("open"), this.onClose = null, this.beforeRender = null, this.selector = null
            }

            return a(e, [{
                key: "render", value: function (e) {
                    var t = arguments.length > 1 && void 0 !== arguments[1] ? arguments[1] : {};
                    if (!this.isOpen) {
                        t.onClose && t.onClose instanceof Function && (this.onClose = t.onClose), t.beforeRender && t.beforeRender instanceof Function && (this.beforeRender = t.beforeRender);
                        var n = this.dialogs[e];
                        if (n) {
                            var o = r(n.template);
                            this.beforeRender && this.beforeRender(), this.base.find(".rdp-dialog__body").append(o), this.interaction = new u(this, n), this._injectModel(this.interaction.model), this.open(), n.render && n.render(this, this.interaction)
                        }
                        return n
                    }
                }
            }, {
                key: "open", value: function () {
                    this.isOpen || (this.client.$.addClass("dialog-active"), this.base.attr("open", !0), this.isOpen = !0, this.client.toolbar.disable(), this.client.snapshots.lock(!0))
                }
            }, {
                key: "close", value: function () {
                    var e = this;
                    this.onClose && setTimeout(function () {
                        e.onClose(), e.onClose = null
                    }, 150), this.client.$.removeClass("dialog-active"), this.base.attr("open", !1), this.base.find(".rdp-dialog__body").empty(), this.activeModel = null, this.interaction = null, this.selector = null, this.isOpen = !1, this.client.toolbar.enable(), this.client.snapshots.lock(!1)
                }
            }, {
                key: "_injectModel", value: function (e) {
                    if (e && (this.activeModel = e), this.activeModel) for (var t in this.activeModel) this.base.find("*[data-model='" + t + "']").text(e[t])
                }
            }, {
                key: "update", value: function () {
                    this._injectModel()
                }
            }]), e
        }();
        n.default = f, n.RDPRender = l
    }, {"./Hookable": 2}], 4: [function (e, t, n) {
        "use strict";

        function o(e) {
            return e && e.__esModule ? e : {default: e}
        }

        function i(e, t) {
            if (!(e instanceof t)) throw new TypeError("Cannot call a class as a function")
        }

        function r(e, t) {
            if (!e) throw new ReferenceError("this hasn't been initialised - super() hasn't been called");
            return !t || "object" != typeof t && "function" != typeof t ? e : t
        }

        function s(e, t) {
            if ("function" != typeof t && null !== t) throw new TypeError("Super expression must either be null or a function, not " + typeof t);
            e.prototype = Object.create(t && t.prototype, {
                constructor: {
                    value: e,
                    enumerable: !1,
                    writable: !0,
                    configurable: !0
                }
            }), t && (Object.setPrototypeOf ? Object.setPrototypeOf(e, t) : e.__proto__ = t)
        }

        Object.defineProperty(n, "__esModule", {value: !0}), n.RDPSnapshotSelector = n.RDPSnapshotService = void 0;
        var a = function () {
            function e(e, t) {
                for (var n = 0; n < t.length; n++) {
                    var o = t[n];
                    o.enumerable = o.enumerable || !1, o.configurable = !0, "value" in o && (o.writable = !0), Object.defineProperty(e, o.key, o)
                }
            }

            return function (t, n, o) {
                return n && e(t.prototype, n), o && e(t, o), t
            }
        }(), c = e("./Hookable"), l = o(c), u = function (e) {
            function t(e, n) {
                i(this, t);
                var o = r(this, (t.__proto__ || Object.getPrototypeOf(t)).call(this));
                return o.$ = e, o.service = n, o.hooks = {added: [], removed: []}, o
            }

            return s(t, e), a(t, [{
                key: "add", value: function (e) {
                    var t = this,
                        n = $('\n      <li data-snapshot-id="' + e.id + '">\n        <figure><img src="' + e.data + '" alt="snapshot" /></figure>\n        <div class="rdp-snapshots--controls">\n          <a href="snapshot:remove"><i class="fa fa-remove"></i></a>\n        </div>\n      </li>\n    ');
                    this.$.prepend(n), this.dispatchHook("added", n), n.find('a[href="snapshot:remove"]').bind("click", function (e) {
                        e.preventDefault(), t.service.locked || (t.service.remove(n.data("snapshotId")), n.remove(), t.dispatchHook("removed"))
                    })
                }
            }]), t
        }(l.default), f = function e(t) {
            i(this, e), this.id = t, this.data = null
        }, d = function (e) {
            function t(e) {
                i(this, t);
                var n = r(this, (t.__proto__ || Object.getPrototypeOf(t)).call(this));
                return n.client = e, n.snapshots = [], n.bar = new u(n.client.$.find("#rdp-snapshot-collection"), n), n.count = 0, n.locked = !1, n.hooks = {
                    create: [],
                    remove: []
                }, n
            }

            return s(t, e), a(t, [{
                key: "create", value: function () {
                    var e = arguments.length > 0 && void 0 !== arguments[0] ? arguments[0] : "";
                    if (!this.locked && 0 != e.length) {
                        var t = new f(this.count);
                        t.data = e, this.snapshots.push(t), this.count = this.count + 1, this.bar.add(t), this.dispatchHook("create", t)
                    }
                }
            }, {
                key: "remove", value: function (e) {
                    var t = !1;
                    this.snapshots.forEach(function (n, o) {
                        n.id == e && (t = o)
                    }), t !== !1 && this.snapshots.splice(t, 1), this.dispatchHook("remove", {})
                }
            }, {
                key: "total", value: function () {
                    return this.snapshots.length
                }
            }, {
                key: "lock", value: function () {
                    var e = arguments.length > 0 && void 0 !== arguments[0] ? arguments[0] : void 0;
                    void 0 === e ? this.locked = !!this.locked : this.locked = e
                }
            }, {
                key: "capture", value: function (e) {
                    return this.client.service.getCanvas().toDataURL()
                }
            }]), t
        }(l.default), h = function (e) {
            function t(e, n) {
                i(this, t);
                var o = r(this, (t.__proto__ || Object.getPrototypeOf(t)).call(this));
                return o.el = e, o.snapshots = [], o.selected = [], o.service = n || null, o.hooks = {
                    submit: [],
                    selected: [],
                    deselected: []
                }, o.populate(function () {
                    o.el.on("submit", function (e) {
                        e.preventDefault(), o.dispatchHook("submit", o.selected)
                    }), o.el.find('input[type="checkbox"]').bind("change", function (e) {
                        var t = $(e.currentTarget);
                        if (t.is(":checked")) {
                            var n = parseInt(t.val()), i = o.service.snapshots.find(function (e) {
                                return e.id == n
                            });
                            o.dispatchHook("selected", i)
                        } else o.dispatchHook("deselected")
                    }), o.on("selected", function (e) {
                        return o.selected.push(e)
                    }), o.on("deselected", function () {
                        return o.selected.pop()
                    })
                }), o
            }

            return s(t, e), a(t, [{
                key: "populate", value: function () {
                    var e = arguments.length > 0 && void 0 !== arguments[0] ? arguments[0] : function () {
                    };
                    if (!this.service) return e();
                    for (var t in this.service.snapshots) {
                        var n = this.service.snapshots[t],
                            o = $('\n        <li>\n          <label for="snapshot-' + n.id + '">\n            <input type="checkbox" name="snapshot-selection[]" value="' + n.id + '" id="snapshot-' + n.id + '" />\n            <span class="snapshot-selection-image">\n              <img src="' + n.data + '" alt="snapshot-' + n.id + '" />\n            </span>\n          </label>\n        </li>\n      ');
                        this.el.find("ul").append(o)
                    }
                    return e()
                }
            }, {
                key: "commit", value: function () {
                    var e = this;
                    return new Promise(function (t, n) {
                        var o = e.selected;
                        $.ajax({
                            url: "/analysis/" + e.service.client.id + "/control/screenshots/",
                            type: "POST",
                            dataType: "json",
                            contentType: "application/json; charset=utf-8",
                            data: JSON.stringify(o),
                            beforeSend: function (request) {
                                let token = Cookies.get("csrftoken");
                                if (!token) {
                                    let field = $("input[name=csrfmiddlewaretoken]");
                                    if (field && field.val()) {
                                        token = field.val();
                                    }
                                }
                                if (token) {
                                    request.setRequestHeader("X-CSRFToken", token);
                                } else {
                                    console.warn("Request to " + url + " on page without CSRF token");
                                }
                            },
                            success: function (e, n) {
                                t()
                            },
                            error: function (e) {
                                n(e)
                            }
                        })
                    })
                }
            }]), t
        }(l.default);
        n.RDPSnapshotService = d, n.RDPSnapshotSelector = h
    }, {"./Hookable": 2}], 5: [function (e, t, n) {
        "use strict";

        function o(e) {
            return e && e.__esModule ? e : {default: e}
        }

        function i(e, t) {
            if (!(e instanceof t)) throw new TypeError("Cannot call a class as a function")
        }

        function r(e, t) {
            if (!e) throw new ReferenceError("this hasn't been initialised - super() hasn't been called");
            return !t || "object" != typeof t && "function" != typeof t ? e : t
        }

        function s(e, t) {
            if ("function" != typeof t && null !== t) throw new TypeError("Super expression must either be null or a function, not " + typeof t);
            e.prototype = Object.create(t && t.prototype, {
                constructor: {
                    value: e,
                    enumerable: !1,
                    writable: !0,
                    configurable: !0
                }
            }), t && (Object.setPrototypeOf ? Object.setPrototypeOf(e, t) : e.__proto__ = t)
        }

        function a(e) {
            return e.ctrlKey || e.metaKey || e.shiftKey || e.altKey
        }

        Object.defineProperty(n, "__esModule", {value: !0});
        var c = function () {
            function e(e, t) {
                for (var n = 0; n < t.length; n++) {
                    var o = t[n];
                    o.enumerable = o.enumerable || !1, o.configurable = !0, "value" in o && (o.writable = !0), Object.defineProperty(e, o.key, o)
                }
            }

            return function (t, n, o) {
                return n && e(t.prototype, n), o && e(t, o), t
            }
        }(), l = e("./Hookable"), u = o(l), f = e("./RDPToolbarButton"), d = function (e) {
            function t(e) {
                i(this, t);
                var n = r(this, (t.__proto__ || Object.getPrototypeOf(t)).call(this));
                return n.client = e, n.buttons = {
                    fullscreen: new f.RDPToolbarButton(e.$.find('button[name="fullscreen"]'), {client: e}),
                    snapshot: new f.RDPSnapshotButton(e.$.find('button[name="screenshot"]'), {client: e}),
                    control: new f.RDPToolbarButton(e.$.find('button[name="control"]'), {client: e, holdToggle: !0})
                }, n.buttons.fullscreen.on("click", function () {
                    CuckooWeb.isFullscreen() ? CuckooWeb.exitFullscreen() : CuckooWeb.requestFullscreen(document.getElementById("rdp-client"))
                }), CuckooWeb.onFullscreenChange(function (e) {
                    return n.client.$.toggleClass("fullscreen", CuckooWeb.isFullscreen())
                }), n.buttons.snapshot.on("click", function () {
                    var e = n.client.snapshots.capture();
                    n.client.snapshots.create(e)
                }), n.buttons.control.on("toggle", function (e) {
                    e ? (n.client.service.mouse(!0), n.client.service.keyboard(!0)) : (n.client.service.mouse(!1), n.client.service.keyboard(!1))
                }), $("body").on("keydown", function (e) {
                    if (!a(e) && !n.buttons.control.toggled) switch (e.keyCode) {
                        case 83:
                            n.buttons.snapshot.dispatchHook("click"), n.buttons.snapshot.blink();
                            break;
                        case 70:
                            n.buttons.fullscreen.dispatchHook("click"), n.buttons.fullscreen.blink();
                            break;
                        case 67:
                            n.buttons.control.$.trigger("mousedown")
                    }
                }), n
            }

            return s(t, e), c(t, [{
                key: "disable", value: function () {
                    for (var e in this.buttons) this.buttons[e].disable(!0)
                }
            }, {
                key: "enable", value: function () {
                    for (var e in this.buttons) this.buttons[e].disable(!1)
                }
            }]), t
        }(u.default);
        n.default = d
    }, {"./Hookable": 2, "./RDPToolbarButton": 6}], 6: [function (e, t, n) {
        "use strict";

        function o(e) {
            return e && e.__esModule ? e : {default: e}
        }

        function i(e, t) {
            if (!(e instanceof t)) throw new TypeError("Cannot call a class as a function")
        }

        function r(e, t) {
            if (!e) throw new ReferenceError("this hasn't been initialised - super() hasn't been called");
            return !t || "object" != typeof t && "function" != typeof t ? e : t
        }

        function s(e, t) {
            if ("function" != typeof t && null !== t) throw new TypeError("Super expression must either be null or a function, not " + typeof t);
            e.prototype = Object.create(t && t.prototype, {
                constructor: {
                    value: e,
                    enumerable: !1,
                    writable: !0,
                    configurable: !0
                }
            }), t && (Object.setPrototypeOf ? Object.setPrototypeOf(e, t) : e.__proto__ = t)
        }

        Object.defineProperty(n, "__esModule", {value: !0}), n.RDPSnapshotButton = n.RDPToolbarButton = void 0;
        var a = function () {
            function e(e, t) {
                for (var n = 0; n < t.length; n++) {
                    var o = t[n];
                    o.enumerable = o.enumerable || !1, o.configurable = !0, "value" in o && (o.writable = !0), Object.defineProperty(e, o.key, o)
                }
            }

            return function (t, n, o) {
                return n && e(t.prototype, n), o && e(t, o), t
            }
        }(), c = e("./Hookable"), l = o(c), u = function (e) {
            function t(e) {
                var n = arguments.length > 1 && void 0 !== arguments[1] ? arguments[1] : {};
                i(this, t);
                var o = r(this, (t.__proto__ || Object.getPrototypeOf(t)).call(this));
                return o.$ = e, o.client = n.client, o.holdToggle = n.holdToggle || !1, o.toggled = o.$.hasClass("active"), o.isDisabled = !!o.$.attr("disabled"), o.hooks = {
                    click: [],
                    toggle: [],
                    disabled: []
                }, o.$.bind("mousedown", function (e) {
                    o.dispatchHook("click", {}), o.holdToggle && (o.$.toggleClass("active"), o.toggled = o.$.hasClass("active"), o.dispatchHook("toggle", o.toggled))
                }), o
            }

            return s(t, e), a(t, [{
                key: "disable", value: function (e) {
                    void 0 === e ? this.$.prop("disabled", !!this.disabled) : this.$.prop("disabled", e), this.disabled = this.$.prop("disabled"), this.dispatchHook("disabled")
                }
            }, {
                key: "blink", value: function () {
                    var e = this;
                    this.$.addClass("active"), setTimeout(function () {
                        return e.$.removeClass("active")
                    }, 150)
                }
            }]), t
        }(l.default), f = function (e) {
            function t(e) {
                var n = arguments.length > 1 && void 0 !== arguments[1] ? arguments[1] : {};
                i(this, t);
                var o = r(this, (t.__proto__ || Object.getPrototypeOf(t)).call(this, e, n));
                return o.$ = o.$.parent(), o
            }

            return s(t, e), a(t, [{
                key: "update", value: function () {
                    var e = this, t = arguments.length > 0 && void 0 !== arguments[0] && arguments[0],
                        n = this.client.snapshots.total();
                    this.$.find(".button-badge").text(n), t ? (2 == n && this.$.find(".ss-v-e-3").removeClass("in"), 1 == n && this.$.find(".ss-v-e-2").removeClass("in"), 0 == n && (this.$.find(".ss-v-e-1").removeClass("in"), this.$.find(".button-badge").text(""))) : (n <= 3 && this.$.find(".ss-v-e-" + n).addClass("in"), this.$.find("button").addClass("shutter-in"), setTimeout(function () {
                        return e.$.find("button").removeClass("shutter-in")
                    }, 1500))
                }
            }, {
                key: "disable", value: function (e) {
                    void 0 === e ? this.$.find("button").prop("disabled", !!this.disabled) : this.$.find("button").prop("disabled", e), this.isDisabled = this.$.find("button").prop("disabled"), this.dispatchHook("disabled", this.isDisabled)
                }
            }]), t
        }(u);
        n.RDPToolbarButton = u, n.RDPSnapshotButton = f
    }, {"./Hookable": 2}], 7: [function (e, t, n) {
        "use strict";

        function o(e) {
            return e && e.__esModule ? e : {default: e}
        }

        function i(e, t) {
            if (!(e instanceof t)) throw new TypeError("Cannot call a class as a function")
        }

        function r(e, t) {
            if (!e) throw new ReferenceError("this hasn't been initialised - super() hasn't been called");
            return !t || "object" != typeof t && "function" != typeof t ? e : t
        }

        function s(e, t) {
            if ("function" != typeof t && null !== t) throw new TypeError("Super expression must either be null or a function, not " + typeof t);
            e.prototype = Object.create(t && t.prototype, {
                constructor: {
                    value: e,
                    enumerable: !1,
                    writable: !0,
                    configurable: !0
                }
            }), t && (Object.setPrototypeOf ? Object.setPrototypeOf(e, t) : e.__proto__ = t)
        }

        var a = function () {
                function e(e, t) {
                    for (var n = 0; n < t.length; n++) {
                        var o = t[n];
                        o.enumerable = o.enumerable || !1, o.configurable = !0, "value" in o && (o.writable = !0), Object.defineProperty(e, o.key, o)
                    }
                }

                return function (t, n, o) {
                    return n && e(t.prototype, n), o && e(t, o), t
                }
            }(), c = e("./Hookable"), l = o(c), u = e("./GuacWrap"), f = o(u), d = e("./RDPToolbar"), h = o(d),
            p = e("./RDPSnapshotService"), b = e("./RDPDialog"), v = o(b), y = function (e) {
                function t(e) {
                    i(this, t);
                    var n = r(this, (t.__proto__ || Object.getPrototypeOf(t)).call(this));
                    n.$ = e || null, n.id = e.data("taskId");
                    var o = n, s = n.id;
                    return n.service = new f.default({
                        display: e.find("#guacamole-display"),
                        client: n
                    }), n.snapshots = new p.RDPSnapshotService(n), n.toolbar = new h.default(n), n.dialog = new v.default(n, {
                        el: e.find("#rdp-dialog"),
                        dialogs: {
                            snapshots: {
                                template: $("template#rdp-dialog-snapshots"), model: {
                                    total: function () {
                                        return n.snapshots.total()
                                    }
                                }, interactions: {
                                    cancel: function (e) {
                                        e.close()
                                    }, proceed: function (e) {
                                        e.selector.el.submit()
                                    }
                                }, render: function (e, t) {
                                    e.selector = new p.RDPSnapshotSelector(e.base.find("form#snapshot-selection-form"), n.snapshots);
                                    var o = function () {
                                        return e.base.find('span[data-model="selected"]').text(e.selector.selected.length)
                                    };
                                    e.selector.on("submit", function (t) {
                                        e.selector.commit().then(function () {
                                            e.close()
                                        }, function (e) {
                                            console.log(e)
                                        })
                                    }), e.selector.on("selected", o), e.selector.on("deselected", o)
                                }
                            },
                            completed: {
                                template: $("template#rdp-dialog-completed"), interactions: {
                                    close: function (e) {
                                        window.close()
                                    }, report: function (e) {
                                        window.location = "/analysis/" + s + "/summary/"
                                    }
                                }
                            }
                        }
                    }), n.errorDialog = new b.RDPRender(n, $("template#rdp-error")), n.connectingDialog = new b.RDPRender(n, $("template#rdp-connecting")), n.connectingDialog.render(), n.snapshots.on("create", function (e) {
                        n.toolbar.buttons.snapshot.update()
                    }), n.snapshots.bar.on("removed", function () {
                        n.toolbar.buttons.snapshot.update(!0)
                    }), setTimeout(function () {
                        n.service.connect(), n.service.on("ended", function () {
                            n.toolbar.disable(), e.find(".rdp-status").addClass("done")
                        }), n.service.checkReady(n.id, !0, "reported").then(function (e, t) {
                            if (e === !0) if (n.snapshots.total() > 0) {
                                n.dialog.render("snapshots", {
                                    onClose: function () {
                                        return o.dialog.render("completed")
                                    }
                                })
                            } else n.dialog.render("completed", {
                                beforeRender: function () {
                                    return o.errorDialog ? o.errorDialog.destroy() : function () {
                                    }
                                }
                            })
                        }).catch(function (e) {
                            return console.log(e)
                        }), n.service.on("error", function () {
                            n.errorDialog.render()
                        })
                    }, 1500), n.commonBindings(), n
                }

                return s(t, e), a(t, [{
                    key: "commonBindings", value: function () {
                        var e = this, t = function () {
                            var t = !1;
                            e.$.find("#toggle-properties").bind("click", function (e) {
                                e.preventDefault(), $(e.currentTarget).toggleClass("active", !t), t = $(e.currentTarget).hasClass("active")
                            }), $("body").bind("click", function (n) {
                                var o = $(n.target), i = o.parents(".rdp-details").length > 0;
                                t && !i && e.$.find("#toggle-properties").trigger("click")
                            })
                        };
                        t()
                    }
                }]), t
            }(l.default);
        $(function () {
            if ($("#rdp-client").length) {
                new y($("#rdp-client"))
            }
        })
    }, {"./GuacWrap": 1, "./Hookable": 2, "./RDPDialog": 3, "./RDPSnapshotService": 4, "./RDPToolbar": 5}]
}, {}, [7]);
//# sourceMappingURL=rdp.js.map
