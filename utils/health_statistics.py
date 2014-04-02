#!/usr/bin/env python
# Copyright (C) 2010-2014 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

"""
Generate Cuckoo health statistics for this server
"""

import sys
import os
import pygal

sys.path.append(os.path.join(os.path.abspath(os.path.dirname(__file__)), ".."))

from lib.cuckoo.core.database import Database
from lib.cuckoo.core.database import TASK_REPORTED, TASK_FAILED_PROCESSING, TASK_FAILED_ANALYSIS
from lib.cuckoo.core.database import TASK_COMPLETED, TASK_PENDING, TASK_RECOVERED, TASK_RUNNING, CRASH_ISSUES
from lib.cuckoo.core.database import DOTNET_ISSUES, ANTI_ISSUES
from lib.cuckoo.common.constants import CUCKOO_ROOT

from lib.cuckoo.core.database import TASK_ISSUE_NONE, TASK_ISSUE_SHORT_API_CALL_LIST, TASK_ISSUE_CRASH, TASK_ISSUE_ANTI
from lib.cuckoo.core.database import TASK_ISSUE_PERFECT

class HealthStatistics():

    def __init__(self, simple=False):
        self.simple = simple
        self.style = {"fill": True,
                      "interpolate": "cubic",
                      "style": pygal.style.LightStyle}
        self.db = Database()
        self.datadir = os.path.join(CUCKOO_ROOT, "data", "html", "statistics")

    def all(self):
        """ Generating all charts
        """
        self.processing_stages_pie()
        self.processing_time_line()
        self.task_status_pie()
        self.task_success_by_machine_bar()

    def processing_time_line(self):
        """ Processing time line graph for the tasks
        """
        name = "processing_time.svg"
        filename = os.path.join(self.datadir, name)
        td = self.db.task_duration()
        items = []
        total = 0
        if td:
            for i in range(max(td), min(td), -1):
                total += td.count(i)
                items.append(total)
        items.reverse()
        line_chart = pygal.Line(fill=self.style["fill"],
                               interpolate=self.style["interpolate"],
                               style=self.style["style"],
                               x_title="Time in minutes",
                               y_title="Number of samples")
        line_chart.title = 'Full processing time, histogram'
        line_chart.x_labels = map(str, range(min(td), max(td)))
        line_chart.add('Full', items)
        line_chart.render_to_file(filename)
        if self.simple:
            return name
        else:
            return filename


    def processing_stages_pie(self):
        """ Showing a pie chart for the stages and time they consume
        """
        name = "stage_pie.svg"
        filename = os.path.join(self.datadir, name)
        stage_list = ["analysis", "processing", "signatures", "reporting"]
        status_pie = pygal.Pie(fill=self.style["fill"],
                               interpolate=self.style["interpolate"],
                               style=self.style["style"])
        status_pie.title = 'Stage percentage'
        for i in stage_list:
            td = self.db.task_duration(stage=i)
            status_pie.add(i, sum(td))
        status_pie.render_to_file(filename)
        if self.simple:
            return name
        else:
            return filename

    def task_status_pie(self):
        """ Showing a pie chart for the task status
        """
        name = "status_pie.svg"
        filename = os.path.join(self.datadir, name)
        status_list = [TASK_COMPLETED, TASK_REPORTED, TASK_PENDING, TASK_RUNNING, TASK_RECOVERED, TASK_FAILED_ANALYSIS, TASK_FAILED_PROCESSING]
        status_pie = pygal.Pie(fill=self.style["fill"],
                               interpolate=self.style["interpolate"],
                               style=self.style["style"])
        status_pie.title = 'Total task status'
        for stat in status_list:
            status_pie.add(stat, self.db.count_tasks(stat))
        status_pie.render_to_file(filename)
        if self.simple:
            return name
        else:
            return filename

    def task_analysis_pie(self):
        """ Showing a pie chart for the task analysis. Viewing problems and issues like Anti-VM, crashes, ...
        """
        name = "analysis_issues_pie.svg"
        filename = os.path.join(self.datadir, name)
        status_list = [("Short API call list", TASK_ISSUE_SHORT_API_CALL_LIST),
                       ("Crash", TASK_ISSUE_CRASH),
                       ("Anti*", TASK_ISSUE_ANTI),
                       ("Ok", TASK_ISSUE_NONE),
                       ("Perfect", TASK_ISSUE_PERFECT)]
        status_pie = pygal.Pie(fill=self.style["fill"],
                               interpolate=self.style["interpolate"],
                               style=self.style["style"])
        status_pie.title = 'Detailed analysis issues'
        for human, stat in status_list:
            status_pie.add(human, self.db.task_analysis_issues(stat))
        status_pie.render_to_file(filename)
        if self.simple:
            return name
        else:
            return filename

    def task_analysis_by_machine_bar(self):
        """ Showing a pie chart for the task analysis. Viewing problems and issues like Anti-VM, crashes, ...
        """
        name = "analysis_issues_by_machine_bar.svg"
        filename = os.path.join(self.datadir, name)
        machines = self.db.list_machines()
        status_list = [("Short API call list", TASK_ISSUE_SHORT_API_CALL_LIST),
                       ("Crash", TASK_ISSUE_CRASH),
                       ("Anti*", TASK_ISSUE_ANTI),
                       ("Ok", TASK_ISSUE_NONE),
                       ("Perfect", TASK_ISSUE_PERFECT)]
        analysis_bar = pygal.StackedBar(fill=self.style["fill"],
                               interpolate=self.style["interpolate"],
                               style=self.style["style"])
        analysis_bar.title = 'Detailed analysis issues'
        lshort = []
        lcrash = []
        lanti = []
        lok = []
        lperfect = []
        label_list = []
        for m in machines:
            label_list.append(m.name)
            lshort.append(self.db.task_analysis_issues(TASK_ISSUE_SHORT_API_CALL_LIST, mid=m.id))
            lcrash.append(self.db.task_analysis_issues(TASK_ISSUE_CRASH, mid=m.id))
            lanti.append(self.db.task_analysis_issues(TASK_ISSUE_ANTI, mid=m.id))
            lok.append(self.db.task_analysis_issues(TASK_ISSUE_NONE, mid=m.id))
            lperfect.append(self.db.task_analysis_issues(TASK_ISSUE_PERFECT, mid=m.id))

        analysis_bar.x_labels = label_list
        analysis_bar.add("Short API call list", lshort)
        analysis_bar.add("Crash", lcrash)
        analysis_bar.add("Anti*", lanti)
        analysis_bar.add("Ok", lok)
        analysis_bar.add("Perfect", lperfect)
        analysis_bar.render_to_file(filename)
        if self.simple:
            return name
        else:
            return filename

    def task_success_by_machine_bar(self):
        """ Generate a bar graph showing success vs fail for the machines
        """
        name = "task_success_by_machine.svg"
        filename = os.path.join(self.datadir, name)
        machines = self.db.list_machines()
        bar_chart = pygal.StackedBar(fill=self.style["fill"],
                                     interpolate=self.style["interpolate"],
                                     style=self.style["style"])
        bar_chart.title = 'Status by machine'
        l_reported = []
        l_pending = []
        l_running = []
        l_completed = []
        l_recovered = []
        l_failed_analysis = []
        l_failed_processing = []
        label_list = []

        for machine in machines:
            label_list.append(machine.name)
            l_reported.append(self.db.count_tasks(status=TASK_REPORTED, mid=machine.id))
            l_pending.append(self.db.count_tasks(status=TASK_PENDING, mid=machine.id))
            l_running.append(self.db.count_tasks(status=TASK_RUNNING, mid=machine.id))
            l_completed.append(self.db.count_tasks(status=TASK_COMPLETED, mid=machine.id))
            l_recovered.append(self.db.count_tasks(status=TASK_RECOVERED, mid=machine.id))
            l_failed_analysis.append(self.db.count_tasks(status=TASK_FAILED_ANALYSIS, mid=machine.id))
            l_failed_processing.append(self.db.count_tasks(status=TASK_FAILED_PROCESSING, mid=machine.id))

        bar_chart.x_labels = label_list
        bar_chart.add('Reported',  l_reported)
        bar_chart.add('Pending',  l_pending)
        bar_chart.add('Running',  l_running)
        bar_chart.add('Completed',  l_completed)
        bar_chart.add('Recovered',  l_recovered)
        bar_chart.add('Failed Analysis',  l_failed_analysis)
        bar_chart.add('Failed Processing',  l_failed_processing)
        bar_chart.render_to_file(filename)
        if self.simple:
            return name
        else:
            return filename

    def analysis_issues_by_file_type(self):
        """ Generate a bar graph showing success vs fail for the different file types
        """

        name = "analysis_issues_by_file_type.svg"
        filename = os.path.join(self.datadir, name)
        file_types = self.db.get_file_types()
        bar_chart = pygal.StackedBar(fill=self.style["fill"],
                                     interpolate=self.style["interpolate"],
                                     style=self.style["style"],
                                     x_label_rotation=80,
                                     truncate_label=50,
                                     height=1000)
        bar_chart.title = 'Issues by file type'
        lshort = []
        lcrash = []
        lanti = []
        lok = []
        lperfect = []
        label_list = []

        for ftype in file_types:
            label_list.append(ftype)
            lshort.append(self.db.task_analysis_issues(TASK_ISSUE_SHORT_API_CALL_LIST, ftype=ftype))
            lcrash.append(self.db.task_analysis_issues(TASK_ISSUE_CRASH, ftype=ftype))
            lanti.append(self.db.task_analysis_issues(TASK_ISSUE_ANTI, ftype=ftype))
            lok.append(self.db.task_analysis_issues(TASK_ISSUE_NONE, ftype=ftype))
            lperfect.append(self.db.task_analysis_issues(TASK_ISSUE_PERFECT, ftype=ftype))

        bar_chart.x_labels = label_list
        bar_chart.add("Short API call list", lshort)
        bar_chart.add("Crash", lcrash)
        bar_chart.add("Anti*", lanti)
        bar_chart.add("Ok", lok)
        bar_chart.add("Perfect", lperfect)
        bar_chart.render_to_file(filename)
        if self.simple:
            return name
        else:
            return filename


        # TODO: Diagram percent of tasks reported per day. Bar graph
        # TODO: Issue tracker. Create signatures for certain cuckoomon crashes: Exit != 0, dbwin/drwatson, mscoree.dll

if __name__ == "__main__":
    hs = HealthStatistics()
    hs.all()