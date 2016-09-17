'use strict';

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

function _possibleConstructorReturn(self, call) { if (!self) { throw new ReferenceError("this hasn't been initialised - super() hasn't been called"); } return call && (typeof call === "object" || typeof call === "function") ? call : self; }

function _inherits(subClass, superClass) { if (typeof superClass !== "function" && superClass !== null) { throw new TypeError("Super expression must either be null or a function, not " + typeof superClass); } subClass.prototype = Object.create(superClass && superClass.prototype, { constructor: { value: subClass, enumerable: false, writable: true, configurable: true } }); if (superClass) Object.setPrototypeOf ? Object.setPrototypeOf(subClass, superClass) : subClass.__proto__ = superClass; }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

/*
 * Copyright (C) 2010-2013 Claudio Guarnieri.
 * Copyright (C) 2014-2016 Cuckoo Foundation.
 * This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
 * See the file 'docs/LICENSE' for copying permission.
 *
 */

var Plots = function Plots(target_div, ui_minimal) {
    _classCallCheck(this, Plots);

    this.sel_targetid = target_div;
    this.ui_minimal = ui_minimal;
    this._ui_minimal_layout = {
        plot_bgcolor: "rgb(255, 255, 255)",
        showlegend: true,
        xaxis: {
            fixedrange: true,
            showgrid: true,
            zeroline: true,
            showline: true,
            mirror: 'ticks'
        },
        yaxis: {
            fixedrange: true,
            showgrid: true,
            zeroline: false,
            showline: false,
            mirror: 'ticks'
        },
        hovermode: false,
        hoverinfo: "none",
        margin: {
            l: 70, r: 70, b: 100, t: 60, pad: 20
        },
        legend: {
            x: 0, y: 1
        }
    };

    this._ui_minimal_options = {
        displaylogo: !this.ui_minimal,
        displayModeBar: !this.ui_minimal,
        scrollZoom: this.ui_minimal
    };
};

var BarChart = function (_Plots) {
    _inherits(BarChart, _Plots);

    function BarChart(target_div, ui_minimal) {
        _classCallCheck(this, BarChart);

        return _possibleConstructorReturn(this, Object.getPrototypeOf(BarChart).call(this, target_div, ui_minimal));
    }

    _createClass(BarChart, [{
        key: 'draw',
        value: function draw(data, title) {
            var ui_minimal_layout = $.extend({}, this._ui_minimal_layout); //shallow copy
            ui_minimal_layout.title = title;

            $(this.sel_targetid).empty();

            Plotly.newPlot(this.sel_targetid, data, ui_minimal_layout, this._ui_minimal_options);
        }
    }]);

    return BarChart;
}(Plots);

//# sourceMappingURL=plots.js.map