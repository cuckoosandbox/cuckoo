/*
 * Copyright (C) 2010-2013 Claudio Guarnieri.
 * Copyright (C) 2014-2016 Cuckoo Foundation.
 * This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
 * See the file 'docs/LICENSE' for copying permission.
 *
 */

class Plots{
    constructor(target_div, ui_minimal){
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
    }
}

class BarChart extends Plots{
    constructor(target_div, ui_minimal){
        super(target_div, ui_minimal);
    }

    draw(data, title){
        let ui_minimal_layout = $.extend({}, this._ui_minimal_layout);  //shallow copy
        ui_minimal_layout.title = title;

        $(this.sel_targetid).empty();

        Plotly.newPlot(this.sel_targetid,
            data, ui_minimal_layout,
            this._ui_minimal_options
        );
    }
}