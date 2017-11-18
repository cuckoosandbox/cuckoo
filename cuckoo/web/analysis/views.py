# Copyright (C) 2013 Claudio Guarnieri.
# Copyright (C) 2014-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import json
import os
import pymongo
import re
import urllib

from bson.objectid import ObjectId

from django.core.exceptions import PermissionDenied, ObjectDoesNotExist
from django.core.urlresolvers import reverse
from django.http import HttpResponse
from django.shortcuts import redirect
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_safe

from cuckoo.core.database import Database, TASK_PENDING
from cuckoo.common.config import config
from cuckoo.common.elastic import elastic
from cuckoo.common.mongo import mongo
from cuckoo.misc import cwd
from cuckoo.processing import network
from cuckoo.web.utils import view_error, render_template, normalize_task

results_db = mongo.db
fs = mongo.grid

@require_safe
def pending(request):
    pending = []
    for task in Database().list_tasks(status=TASK_PENDING, limit=500):
        pending.append(normalize_task(task.to_dict()))

    return render_template(request, "analysis/pending.html", **{
        "tasks": pending,
    })

@require_safe
def chunk(request, task_id, pid, pagenum):
    try:
        pid, pagenum = int(pid), int(pagenum)-1
    except:
        raise PermissionDenied

    if not request.is_ajax():
        raise PermissionDenied

    record = results_db.analysis.find_one(
        {
            "info.id": int(task_id),
            "behavior.processes.pid": pid
        },
        {
            "behavior.processes.pid": 1,
            "behavior.processes.calls": 1
        }
    )

    if not record:
        raise ObjectDoesNotExist

    process = None
    for pdict in record["behavior"]["processes"]:
        if pdict["pid"] == pid:
            process = pdict

    if not process:
        raise ObjectDoesNotExist

    if pagenum >= 0 and pagenum < len(process["calls"]):
        objectid = process["calls"][pagenum]
        chunk = results_db.calls.find_one({"_id": ObjectId(objectid)})
        for idx, call in enumerate(chunk["calls"]):
            call["id"] = pagenum * 100 + idx
    else:
        chunk = dict(calls=[])

    return render_template(request, "analysis/pages/behavior/_chunk.html", **{
        "chunk": chunk,
    })

@require_safe
def filtered_chunk(request, task_id, pid, category):
    """Filters calls for call category.
    @param task_id: cuckoo task id
    @param pid: pid you want calls
    @param category: call category type
    """
    if not request.is_ajax():
        raise PermissionDenied

    # Search calls related to your PID.
    record = results_db.analysis.find_one(
        {
            "info.id": int(task_id),
            "behavior.processes.pid": int(pid),
        },
        {
            "behavior.processes.pid": 1,
            "behavior.processes.calls": 1,
        }
    )

    if not record:
        raise ObjectDoesNotExist

    # Extract embedded document related to your process from response collection.
    process = None
    for pdict in record["behavior"]["processes"]:
        if pdict["pid"] == int(pid):
            process = pdict

    if not process:
        raise ObjectDoesNotExist

    # Create empty process dict for AJAX view.
    filtered_process = {
        "pid": pid,
        "calls": [],
    }

    # Populate dict, fetching data from all calls and selecting only appropriate category.
    for call in process["calls"]:
        chunk = results_db.calls.find_one({"_id": call})
        for call in chunk["calls"]:
            if call["category"] == category:
                filtered_process["calls"].append(call)

    return render_template(request, "analysis/pages/behavior/_chunk.html", **{
        "chunk": filtered_process,
    })

@csrf_exempt
def search_behavior(request, task_id):
    if request.method != "POST":
        raise PermissionDenied

    query = request.POST.get("search")
    query = re.compile(query, re.I)
    results = []

    # Fetch analysis report.
    record = results_db.analysis.find_one(
        {
            "info.id": int(task_id),
        }
    )

    # Loop through every process
    for process in record["behavior"]["processes"]:
        process_results = []

        chunks = results_db.calls.find({
            "_id": {"$in": process["calls"]}
        })

        index = -1
        for chunk in chunks:
            for call in chunk["calls"]:
                index += 1

                if query.search(call["api"]):
                    call["id"] = index
                    process_results.append(call)
                    continue

                for key, value in call["arguments"].items():
                    if query.search(key):
                        call["id"] = index
                        process_results.append(call)
                        break

                    if isinstance(value, basestring) and query.search(value):
                        call["id"] = index
                        process_results.append(call)
                        break

                    if isinstance(value, (tuple, list)):
                        for arg in value:
                            if not isinstance(arg, basestring):
                                continue

                            if query.search(arg):
                                call["id"] = index
                                process_results.append(call)
                                break
                        else:
                            continue
                        break

        if process_results:
            results.append({
                "process": process,
                "signs": process_results
            })

    return render_template(request, "analysis/pages/behavior/_search_results.html", **{
        "results": results,
    })

@require_safe
def latest_report(request):
    report = results_db.analysis.find_one({
    }, sort=[("_id", pymongo.DESCENDING)])
    if not report:
        return view_error(request, "No analysis has been found")

    return redirect(reverse(
        "analysis", args=(report["info"]["id"], "summary")
    ), permanent=False)

@require_safe
def file(request, category, object_id, fetch="fetch"):
    if not object_id:
        return view_error(request, "File not found")

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

        if fetch != "nofetch":
            response["Content-Disposition"] = (
                "attachment; filename=%s" % file_name
            )
        return response
    else:
        return view_error(request, "File not found")

moloch_mapper = {
    "ip": "ip == %s",
    "host": "host == %s",
    "src_ip": "ip == %s",
    "src_port": "port == %s",
    "dst_ip": "ip == %s",
    "dst_port": "port == %s",
    "sid": 'tags == "sid:%s"',
}

@require_safe
def moloch(request, **kwargs):
    if not config("reporting:moloch:enabled"):
        return view_error(request, "Moloch is not enabled!")

    query = []
    for key, value in kwargs.items():
        if value and value != "None":
            query.append(moloch_mapper[key] % value)

    if ":" in request.get_host():
        hostname = request.get_host().split(":")[0]
    else:
        hostname = request.get_host()

    if config("reporting:moloch:insecure"):
        url = "http://"
    else:
        url = "https://"

    url += "%s:8005/?%s" % (
        config("reporting:moloch:host") or hostname,
        urllib.urlencode({
            "date": "-1",
            "expression": " && ".join(query),
        }),
    )
    return redirect(url)

@require_safe
def full_memory_dump_file(request, analysis_number):
    file_path = cwd("storage", "analyses", "%s" % analysis_number, "memory.dmp")
    if os.path.exists(file_path):
        content_type = "application/octet-stream"
        response = HttpResponse(open(file_path, "rb").read(), content_type=content_type)
        response["Content-Disposition"] = "attachment; filename=memory.dmp"
        return response
    else:
        return view_error(request, "File not found")

def _search_helper(obj, k, value):
    r = []

    if isinstance(obj, dict):
        for k, v in obj.items():
            r += _search_helper(v, k, value)

    if isinstance(obj, (tuple, list)):
        for v in obj:
            r += _search_helper(v, k, value)

    if isinstance(obj, basestring):
        if re.search(value, obj, re.I):
            r.append((k, obj))

    return r

@csrf_exempt
def search(request):
    """New Search API using ElasticSearch as backend."""
    if not elastic.enabled:
        return view_error(request, "ElasticSearch is not enabled and therefore it "
                                   "is not possible to do a global search.")

    if request.method == "GET":
        return render_template(request, "analysis/search.html")

    value = request.POST["search"]

    match_value = ".*".join(re.split("[^a-zA-Z0-9]+", value.lower()))

    r = elastic.client.search(
        index=elastic.index + "-*",
        body={
            "query": {
                "query_string": {
                    "query": '"%s"*' % value,
                },
            },
        }
    )

    analyses = []
    for hit in r["hits"]["hits"]:
        # Find the actual matches in this hit and limit to 8 matches.
        matches = _search_helper(hit, "none", match_value)
        if not matches:
            continue

        analyses.append({
            "task_id": hit["_source"]["report_id"],
            "matches": matches[:16],
            "total": max(len(matches)-16, 0),
        })

    if request.POST.get("raw"):
        return render_template(request, "analysis/search_results.html", **{
            "analyses": analyses,
            "term": request.POST["search"],
        })

    return render_template(request, "analysis/search.html", **{
        "analyses": analyses,
        "term": request.POST["search"],
        "error": None,
    })

@require_safe
def remove(request, task_id):
    """Remove an analysis.
    @todo: remove folder from storage.
    """
    analyses = results_db.analysis.find({"info.id": int(task_id)})

    # Checks if more analysis found with the same ID, like if process.py
    # was run manually.
    if analyses.count() > 1:
        message = (
            "Multiple tasks with this ID deleted, thanks for all the fish "
            "(the specified analysis was present multiple times in mongo)."
        )
    elif analyses.count() == 1:
        message = "Task deleted, thanks for all the fish."

    if not analyses.count():
        return view_error(request, "The specified analysis does not exist")

    for analysis in analyses:
        # Delete sample if not used.
        if "file_id" in analysis["target"]:
            if results_db.analysis.find({"target.file_id": ObjectId(analysis["target"]["file_id"])}).count() == 1:
                fs.delete(ObjectId(analysis["target"]["file_id"]))

        # Delete screenshots.
        for shot in analysis["shots"]:
            if isinstance(shot, dict):
                if "small" in shot:
                    if results_db.analysis.find({
                        "shots": ObjectId(shot["small"]),
                    }).count() == 1:
                        fs.delete(ObjectId(shot["small"]))

                if "original" in shot:
                    if results_db.analysis.find({
                        "shots": ObjectId(shot["original"]),
                    }).count() == 1:
                        fs.delete(ObjectId(shot["original"]))

                continue

            if results_db.analysis.find({"shots": ObjectId(shot)}).count() == 1:
                fs.delete(ObjectId(shot))

        # Delete network pcap.
        if "pcap_id" in analysis["network"] and results_db.analysis.find({"network.pcap_id": ObjectId(analysis["network"]["pcap_id"])}).count() == 1:
            fs.delete(ObjectId(analysis["network"]["pcap_id"]))

        # Delete sorted pcap
        if "sorted_pcap_id" in analysis["network"] and results_db.analysis.find({"network.sorted_pcap_id": ObjectId(analysis["network"]["sorted_pcap_id"])}).count() == 1:
            fs.delete(ObjectId(analysis["network"]["sorted_pcap_id"]))

        # Delete mitmproxy dump.
        if "mitmproxy_id" in analysis["network"] and results_db.analysis.find({"network.mitmproxy_id": ObjectId(analysis["network"]["mitmproxy_id"])}).count() == 1:
            fs.delete(ObjectId(analysis["network"]["mitmproxy_id"]))

        # Delete dropped.
        for drop in analysis.get("dropped", []):
            if "object_id" in drop and results_db.analysis.find({"dropped.object_id": ObjectId(drop["object_id"])}).count() == 1:
                fs.delete(ObjectId(drop["object_id"]))

        # Delete calls.
        for process in analysis.get("behavior", {}).get("processes", []):
            for call in process["calls"]:
                results_db.calls.remove({"_id": ObjectId(call)})

        # Delete analysis data.
        results_db.analysis.remove({"_id": ObjectId(analysis["_id"])})

    # Delete from SQL db.
    db = Database()
    db.delete_task(task_id)

    return render_template(request, "success.html", **{
        "message": message,
    })

@require_safe
def pcapstream(request, task_id, conntuple):
    """Get packets from the task PCAP related to a certain connection.
    This is possible because we sort the PCAP during processing and remember offsets for each stream.
    """
    src, sport, dst, dport, proto = conntuple.split(",")
    sport, dport = int(sport), int(dport)

    conndata = results_db.analysis.find_one(
        {
            "info.id": int(task_id),
        },
        {
            "network.tcp": 1,
            "network.udp": 1,
            "network.sorted_pcap_id": 1,
        },
        sort=[("_id", pymongo.DESCENDING)])

    if not conndata:
        return view_error(request, "The specified analysis does not exist")

    try:
        if proto == "udp":
            connlist = conndata["network"]["udp"]
        else:
            connlist = conndata["network"]["tcp"]

        conns = filter(lambda i: (i["sport"], i["dport"], i["src"], i["dst"]) == (sport, dport, src, dst), connlist)
        stream = conns[0]
        offset = stream["offset"]
    except:
        return view_error(request, "Could not find the requested stream")

    try:
        fobj = fs.get(conndata["network"]["sorted_pcap_id"])
        setattr(fobj, "fileno", lambda: -1)
    except:
        return view_error("The required sorted PCAP does not exist")

    packets = list(network.packets_for_stream(fobj, offset))
    # TODO: starting from django 1.7 we should use JsonResponse.
    return HttpResponse(json.dumps(packets), content_type="application/json")
