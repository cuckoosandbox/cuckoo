# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import sys
import re
import os
import json

from django.conf import settings
from django.template import RequestContext
from django.http import HttpResponse
from django.shortcuts import render_to_response
from django.views.decorators.http import require_safe
from django.views.decorators.csrf import csrf_exempt

import pymongo
from bson.objectid import ObjectId
from django.core.exceptions import PermissionDenied
from gridfs import GridFS

sys.path.append(settings.CUCKOO_PATH)

from lib.cuckoo.core.database import Database, TASK_PENDING
from lib.cuckoo.common.constants import CUCKOO_ROOT
import modules.processing.network as network

results_db = pymongo.MongoClient(settings.MONGO_HOST, settings.MONGO_PORT)[settings.MONGO_DB]
fs = GridFS(results_db)

@require_safe
def index(request):
    db = Database()
    tasks_files = db.list_tasks(limit=50, category="file", not_status=TASK_PENDING)
    tasks_urls = db.list_tasks(limit=50, category="url", not_status=TASK_PENDING)

    analyses_files = []
    analyses_urls = []

    if tasks_files:
        for task in tasks_files:
            new = task.to_dict()
            new["sample"] = db.view_sample(new["sample_id"]).to_dict()

            filename = os.path.basename(new["target"])
            new.update({"filename": filename})

            if db.view_errors(task.id):
                new["errors"] = True

            analyses_files.append(new)

    if tasks_urls:
        for task in tasks_urls:
            new = task.to_dict()

            if db.view_errors(task.id):
                new["errors"] = True

            analyses_urls.append(new)

    return render_to_response("analysis/index.html",
                              {"files": analyses_files, "urls": analyses_urls},
                              context_instance=RequestContext(request))

@require_safe
def pending(request):
    db = Database()
    tasks = db.list_tasks(status=TASK_PENDING)

    pending = []
    for task in tasks:
        pending.append(task.to_dict())

    return render_to_response("analysis/pending.html",
                              {"tasks": pending},
                              context_instance=RequestContext(request))

@require_safe
def chunk(request, task_id, pid, pagenum):
    try:
        pid, pagenum = int(pid), int(pagenum)-1
    except:
        raise PermissionDenied

    if request.is_ajax():
        record = results_db.analysis.find_one(
            {
                "info.id": int(task_id),
                "behavior.processes.process_id": pid
            },
            {
                "behavior.processes.process_id": 1,
                "behavior.processes.calls": 1
            }
        )

        if not record:
            raise PermissionDenied

        process = None
        for pdict in record["behavior"]["processes"]:
            if pdict["process_id"] == pid:
                process = pdict

        if not process:
            raise PermissionDenied

        objectid = process["calls"][pagenum]
        chunk = results_db.calls.find_one({"_id": ObjectId(objectid)})

        return render_to_response("analysis/behavior/_chunk.html",
                                  {"chunk": chunk},
                                  context_instance=RequestContext(request))
    else:
        raise PermissionDenied


@require_safe
def filtered_chunk(request, task_id, pid, category):
    """Filters calls for call category.
    @param task_id: cuckoo task id
    @param pid: pid you want calls
    @param category: call category type
    """
    if request.is_ajax():
        # Search calls related to your PID.
        record = results_db.analysis.find_one(
            {"info.id": int(task_id), "behavior.processes.process_id": int(pid)},
            {"behavior.processes.process_id": 1, "behavior.processes.calls": 1}
        )

        if not record:
            raise PermissionDenied

        # Extract embedded document related to your process from response collection.
        process = None
        for pdict in record["behavior"]["processes"]:
            if pdict["process_id"] == int(pid):
                process = pdict

        if not process:
            raise PermissionDenied

        # Create empty process dict for AJAX view.
        filtered_process = {"process_id": pid, "calls": []}

        # Populate dict, fetching data from all calls and selecting only appropriate category.
        for call in process["calls"]:
            chunk = results_db.calls.find_one({"_id": call})
            for call in chunk["calls"]:
                if call["category"] == category:
                    filtered_process["calls"].append(call)

        return render_to_response("analysis/behavior/_chunk.html",
                                  {"chunk": filtered_process},
                                  context_instance=RequestContext(request))
    else:
        raise PermissionDenied

@csrf_exempt
def search_behavior(request, task_id):
    if request.method == "POST":
        query = request.POST.get("search")
        results = []

        # Fetch anaylsis report
        record = results_db.analysis.find_one(
            {"info.id": int(task_id)}
        )

        # Loop through every process
        for process in record["behavior"]["processes"]:
            process_results = []

            chunks = results_db.calls.find({
                "_id": { "$in": process["calls"] }
            })
            for chunk in chunks:
                for call in chunk["calls"]:
                    query = re.compile(query)
                    if query.search(call["api"]):
                        process_results.append(call)
                    else:
                        for argument in call["arguments"]:
                            if query.search(argument["name"]) or query.search(argument["value"]):
                                process_results.append(call)
                                break

            if len(process_results) > 0:
                results.append({
                    "process": process,
                    "signs": process_results
                })

        return render_to_response("analysis/behavior/_search_results.html",
                                  {"results": results},
                                  context_instance=RequestContext(request))
    else:
        raise PermissionDenied

@require_safe
def report(request, task_id):
    report = results_db.analysis.find_one({"info.id": int(task_id)}, sort=[("_id", pymongo.DESCENDING)])

    if not report:
        return render_to_response("error.html",
                                  {"error": "The specified analysis does not exist"},
                                  context_instance=RequestContext(request))

    # Creating dns information dicts by domain and ip.
    if "network" in report and "domains" in report["network"]:
        domainlookups = dict((i["domain"], i["ip"]) for i in report["network"]["domains"])
        iplookups = dict((i["ip"], i["domain"]) for i in report["network"]["domains"])
        for i in report["network"]["dns"]:
            for a in i["answers"]:
                iplookups[a["data"]] = i["request"]
    else:
        domainlookups = dict()
        iplookups = dict()

    return render_to_response("analysis/report.html",
                              {"analysis": report, "domainlookups": domainlookups, "iplookups": iplookups},
                              context_instance=RequestContext(request))

@require_safe
def file(request, category, object_id):
    file_item = fs.get(ObjectId(object_id))

    if file_item:
        # Composing file name in format sha256_originalfilename.
        file_name = file_item.sha256 + "_" + file_item.filename

        # Managing gridfs error if field contentType is missing.
        try:
            content_type = file_item.contentType
        except AttributeError:
            content_type = "application/octet-stream"

        response = HttpResponse(file_item.read(), content_type=content_type)
        response["Content-Disposition"] = "attachment; filename={0}".format(file_name)

        return response
    else:
        return render_to_response("error.html",
                                  {"error": "File not found"},
                                  context_instance=RequestContext(request))


@require_safe
def full_memory_dump_file(request, analysis_number):
    file_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(analysis_number), "memory.dmp")
    if os.path.exists(file_path):
        content_type = "application/octet-stream"
        response = HttpResponse(open(file_path, "rb").read(), content_type=content_type)
        response["Content-Disposition"] = "attachment; filename=memory.dmp"

        return response
    else:
        return render_to_response("error.html",
                                  {"error": "File not found"},
                                  context_instance=RequestContext(request))


def search(request):
    if "search" in request.POST:
        error = None

        try:
            term, value = request.POST["search"].strip().split(":", 1)
        except ValueError:
            term = ""
            value = request.POST["search"].strip()

        if term:
            # Check on search size.
            if len(value) < 3:
                return render_to_response("analysis/search.html",
                                          {"analyses": None,
                                           "term": request.POST["search"],
                                           "error": "Search term too short, minimum 3 characters required"},
                                          context_instance=RequestContext(request))
            # name:foo or name: foo
            value = value.lstrip()

            # Search logic.
            if term == "name":
                records = results_db.analysis.find({"target.file.name": {"$regex": value, "$options": "-i"}}).sort([["_id", -1]])
            elif term == "type":
                records = results_db.analysis.find({"target.file.type": {"$regex": value, "$options": "-i"}}).sort([["_id", -1]])
            elif term == "string":
                records = results_db.analysis.find({"strings" : {"$regex" : value, "$options" : "-1"}}).sort([["_id", -1]])
            elif term == "ssdeep":
                records = results_db.analysis.find({"target.file.ssdeep": {"$regex": value, "$options": "-i"}}).sort([["_id", -1]])
            elif term == "crc32":
                records = results_db.analysis.find({"target.file.crc32": value}).sort([["_id", -1]])
            elif term == "file":
                records = results_db.analysis.find({"behavior.summary.files": {"$regex": value, "$options": "-i"}}).sort([["_id", -1]])
            elif term == "key":
                records = results_db.analysis.find({"behavior.summary.keys": {"$regex": value, "$options": "-i"}}).sort([["_id", -1]])
            elif term == "mutex":
                records = results_db.analysis.find({"behavior.summary.mutexes": {"$regex": value, "$options": "-i"}}).sort([["_id", -1]])
            elif term == "domain":
                records = results_db.analysis.find({"network.domains.domain": {"$regex": value, "$options": "-i"}}).sort([["_id", -1]])
            elif term == "ip":
                records = results_db.analysis.find({"network.hosts": value}).sort([["_id", -1]])
            elif term == "signature":
                records = results_db.analysis.find({"signatures.description": {"$regex": value, "$options": "-i"}}).sort([["_id", -1]])
            elif term == "url":
                records = results_db.analysis.find({"target.url": value}).sort([["_id", -1]])
            elif term == "imphash":
                records = results_db.analysis.find({"static.pe_imphash": value}).sort([["_id", -1]])
            else:
                return render_to_response("analysis/search.html",
                                          {"analyses": None,
                                           "term": request.POST["search"],
                                           "error": "Invalid search term: %s" % term},
                                          context_instance=RequestContext(request))
        else:
            value = value.lower()

            if re.match(r"^([a-fA-F\d]{32})$", value):
                records = results_db.analysis.find({"target.file.md5": value}).sort([["_id", -1]])
            elif re.match(r"^([a-fA-F\d]{40})$", value):
                records = results_db.analysis.find({"target.file.sha1": value}).sort([["_id", -1]])
            elif re.match(r"^([a-fA-F\d]{64})$", value):
                records = results_db.analysis.find({"target.file.sha256": value}).sort([["_id", -1]])
            elif re.match(r"^([a-fA-F\d]{128})$", value):
                records = results_db.analysis.find({"target.file.sha512": value}).sort([["_id", -1]])
            else:
                return render_to_response("analysis/search.html",
                                          {"analyses": None,
                                           "term": None,
                                           "error": "Unable to recognize the search syntax"},
                                          context_instance=RequestContext(request))

        # Get data from cuckoo db.
        db = Database()
        analyses = []

        for result in records:
            new = db.view_task(result["info"]["id"])

            if not new:
                continue

            new = new.to_dict()

            if result["info"]["category"] == "file":
                if new["sample_id"]:
                    sample = db.view_sample(new["sample_id"])
                    if sample:
                        new["sample"] = sample.to_dict()

            analyses.append(new)

        return render_to_response("analysis/search.html",
                                  {"analyses": analyses,
                                   "term": request.POST["search"],
                                   "error": None},
                                  context_instance=RequestContext(request))
    else:
        return render_to_response("analysis/search.html",
                                  {"analyses": None,
                                   "term": None,
                                   "error": None},
                                  context_instance=RequestContext(request))

@require_safe
def remove(request, task_id):
    """Remove an analysis.
    @todo: remove folder from storage.
    """
    anals = results_db.analysis.find({"info.id": int(task_id)})

    # Checks if more analysis found with the same ID, like if process.py was run manually.
    if anals.count() > 1:
        message = "Multiple tasks with this ID deleted, thanks for all the fish. (The specified analysis was duplicated in mongo)"
    elif anals.count() == 1:
        message = "Task deleted, thanks for all the fish."

    if anals.count() > 0:
        # Delete dups too.
        for analysis in anals:
            # Delete sample if not used.
            if "file_id" in analysis["target"]:
                if results_db.analysis.find({"target.file_id": ObjectId(analysis["target"]["file_id"])}).count() == 1:
                    fs.delete(ObjectId(analysis["target"]["file_id"]))
            # Delete screenshots.
            for shot in analysis["shots"]:
                if results_db.analysis.find({"shots": ObjectId(shot)}).count() == 1:
                    fs.delete(ObjectId(shot))
            # Delete network pcap.
            if "pcap_id" in analysis["network"] and results_db.analysis.find({"network.pcap_id": ObjectId(analysis["network"]["pcap_id"])}).count() == 1:
                fs.delete(ObjectId(analysis["network"]["pcap_id"]))
            
            # Delete sorted pcap
            if "sorted_pcap_id" in analysis["network"] and results_db.analysis.find({"network.sorted_pcap_id": ObjectId(analysis["network"]["sorted_pcap_id"])}).count() == 1:
                fs.delete(ObjectId(analysis["network"]["sorted_pcap_id"]))
                
            # Delete dropped.
            for drop in analysis["dropped"]:
                if "object_id" in drop and results_db.analysis.find({"dropped.object_id": ObjectId(drop["object_id"])}).count() == 1:
                    fs.delete(ObjectId(drop["object_id"]))
            # Delete calls.
            for process in analysis["behavior"]["processes"]:
                for call in process["calls"]:
                    results_db.calls.remove({"_id": ObjectId(call)})
            # Delete analysis data.
            results_db.analysis.remove({"_id": ObjectId(analysis["_id"])})
    else:
        return render_to_response("error.html",
                                  {"error": "The specified analysis does not exist"},
                                  context_instance=RequestContext(request))

    # Delete from SQL db.
    db = Database()
    db.delete_task(task_id)

    return render_to_response("success.html",
                              {"message": message},
                              context_instance=RequestContext(request))

@require_safe
def pcapstream(request, task_id, conntuple):
    """Get packets from the task PCAP related to a certain connection.
    This is possible because we sort the PCAP during processing and remember offsets for each stream.
    """
    src, sport, dst, dport, proto = conntuple.split(",")
    sport, dport = int(sport), int(dport)

    conndata = results_db.analysis.find_one({"info.id": int(task_id)},
        {"network.tcp": 1, "network.udp": 1, "network.sorted_pcap_id": 1},
        sort=[("_id", pymongo.DESCENDING)])

    if not conndata:
        return render_to_response("standalone_error.html",
            {"error": "The specified analysis does not exist"},
            context_instance=RequestContext(request))

    try:
        if proto == "udp": connlist = conndata["network"]["udp"]
        else: connlist = conndata["network"]["tcp"]

        conns = filter(lambda i: (i["sport"], i["dport"], i["src"], i["dst"]) == (sport, dport, src, dst),
            connlist)
        stream = conns[0]
        offset = stream["offset"]
    except:
        return render_to_response("standalone_error.html",
            {"error": "Could not find the requested stream"},
            context_instance=RequestContext(request))

    try:
        fobj = fs.get(conndata["network"]["sorted_pcap_id"])
        # Gridfs gridout has no fileno(), which is needed by dpkt pcap reader for NOTHING.
        setattr(fobj, "fileno", lambda: -1)
    except:
        return render_to_response("standalone_error.html",
            {"error": "The required sorted PCAP does not exist"},
            context_instance=RequestContext(request))

    packets = list(network.packets_for_stream(fobj, offset))
    # TODO: starting from django 1.7 we should use JsonResponse.
    return HttpResponse(json.dumps(packets), content_type="application/json")
