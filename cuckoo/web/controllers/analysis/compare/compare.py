# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file "docs/LICENSE" for copying permission.

from cuckoo.common.compare import helper_percentages_mongo
from cuckoo.common.mongo import mongo

results_db = mongo.db

class AnalysisCompareController:
    @staticmethod
    def left(task_id):
        analysis = AnalysisCompareController.get_analysis(task_id)

        if analysis["target"]["category"] == "url":
            # Select all analyses for the same URL.
            records = results_db.analysis.find(
                {
                    "$and": [
                        {"target.url": analysis["target"]["url"]},
                        {"info.id": {"$ne": int(task_id)}}
                    ]
                },
                {"target": 1, "info": 1}
            )
        else:
            # Select all analyses with same file hash.
            records = results_db.analysis.find(
                {
                    "$and": [
                        {"target.file.md5": analysis["target"]["file"]["md5"]},
                        {"info.id": {"$ne": int(task_id)}}
                    ]
                },
                {"target": 1, "info": 1}
            )

        return {
            "report": {"analysis": analysis},  # TO-DO: dirty hack for url resolve @ sidebar.html
            "left": analysis,
            "records": records
        }

    @staticmethod
    def hash(task_id, compare_with_hash):
        analysis = AnalysisCompareController.get_analysis(task_id)

        # If the analysis is not of a file, but of a URL, we consider the hash
        # to be a URL instead.
        if analysis["target"]["category"] == "url":
            records = results_db.analysis.find(
                {
                    "$and": [
                        {"target.url": {"$regex": compare_with_hash, "$options": "-i"}},
                        {"info.id": {"$ne": int(task_id)}}
                    ]
                },
                {"target": 1, "info": 1}
            )
        else:
            records = results_db.analysis.find(
                {
                    "$and": [
                        {"target.file.md5": compare_with_hash},
                        {"info.id": {"$ne": int(task_id)}}
                    ]
                },
                {"target": 1, "info": 1}
            )

        # Select all analyses with specified file hash.
        return {
            "report": {"analysis": analysis},  # TO-DO: dirty hack for url resolve @ sidebar.html
            "left": analysis,
            "records": records,
            "hash": compare_with_hash,
        }

    @staticmethod
    def both(task_id, compare_with_task_id):
        analysis_1 = AnalysisCompareController.get_analysis(task_id)
        analysis_2 = AnalysisCompareController.get_analysis(compare_with_task_id)

        # Execute comparison.
        counts = helper_percentages_mongo(
            results_db, task_id, compare_with_task_id
        )

        return {
            "report": {"analysis": analysis_1},  # TO-DO: dirty hack for url resolve @ sidebar.html
            "left": analysis_1,
            "right": analysis_2,
            "left_counts": counts[task_id],
            "right_counts": counts[compare_with_task_id],
        }

    @staticmethod
    def get_analysis(analysis_id):
        analysis = results_db.analysis.find_one({"info.id": int(analysis_id)}, {"target": 1, "info": 1})
        if not analysis:
            raise Exception("No analysis found with specified ID")

        return analysis
