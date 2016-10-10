# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import calendar
import datetime
import sys
import re
import os
import json
import urllib
import zipfile

from cStringIO import StringIO

from django.conf import settings
from django.http import HttpResponse
from django.shortcuts import render, redirect
from django.views.decorators.http import require_safe
from django.views.decorators.csrf import csrf_exempt

import pymongo
from bson.objectid import ObjectId
from django.core.exceptions import PermissionDenied, ObjectDoesNotExist
from gridfs import GridFS

sys.path.insert(0, settings.CUCKOO_PATH)

from lib.cuckoo.core.database import Database, TASK_PENDING, TASK_COMPLETED
from lib.cuckoo.common.utils import store_temp_file, versiontuple
from lib.cuckoo.common.constants import CUCKOO_ROOT, LATEST_HTTPREPLAY
import modules.processing.network as network

results_db = settings.MONGO
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

    return render(request, "analysis/index.html", {
        "files": analyses_files,
        "urls": analyses_urls,
    })

@require_safe
def pending(request):
    db = Database()
    tasks = db.list_tasks(status=TASK_PENDING)

    pending = []
    for task in tasks:
        pending.append(task.to_dict())

    return render(request, "analysis/pending.html", {
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

    return render(request, "analysis/behavior/_chunk.html", {
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

    return render(request, "analysis/behavior/_chunk.html", {
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

    return render(request, "analysis/behavior/_search_results.html", {
        "results": results,
    })

@require_safe
def report(request, task_id):
    report = results_db.analysis.find_one({"info.id": int(task_id)}, sort=[("_id", pymongo.DESCENDING)])

    if not report:
        return render(request, "error.html", {
            "error": "The specified analysis does not exist",
        })

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

    if "http_ex" in report["network"] or "https_ex" in report["network"]:
        HAVE_HTTPREPLAY = True
    else:
        HAVE_HTTPREPLAY = False

    try:
        import httpreplay
        httpreplay_version = getattr(httpreplay, "__version__", None)
    except ImportError:
        httpreplay_version = None

    # Is this version of httpreplay deprecated?
    deprecated = httpreplay_version and \
        versiontuple(httpreplay_version) < versiontuple(LATEST_HTTPREPLAY)

    return render(request, "analysis/report.html", {
        "analysis": report,
        "domainlookups": domainlookups,
        "iplookups": iplookups,
        "httpreplay": {
            "have": HAVE_HTTPREPLAY,
            "deprecated": deprecated,
            "current_version": httpreplay_version,
            "latest_version": LATEST_HTTPREPLAY,
        },
    })

@require_safe
def latest_report(request):
    rep = results_db.analysis.find_one({}, sort=[("_id", pymongo.DESCENDING)])
    return report(request, rep["info"]["id"] if rep else 0)

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
        response["Content-Disposition"] = "attachment; filename=%s" % file_name

        return response
    else:
        return render(request, "error.html", {
            "error": "File not found",
        })

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
    if not settings.MOLOCH_ENABLED:
        return render(request, "error.html", {
            "error": "Moloch is not enabled!",
        })

    query = []
    for key, value in kwargs.items():
        if value and value != "None":
            query.append(moloch_mapper[key] % value)

    if ":" in request.get_host():
        hostname = request.get_host().split(":")[0]
    else:
        hostname = request.get_host()

    url = "https://%s:8005/?%s" % (
        settings.MOLOCH_HOST or hostname,
        urllib.urlencode({
            "date": "-1",
            "expression": " && ".join(query),
        }),
    )
    return redirect(url)

@require_safe
def full_memory_dump_file(request, analysis_number):
    file_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(analysis_number), "memory.dmp")
    if os.path.exists(file_path):
        content_type = "application/octet-stream"
        response = HttpResponse(open(file_path, "rb").read(), content_type=content_type)
        response["Content-Disposition"] = "attachment; filename=memory.dmp"
        return response
    else:
        return render(request, "error.html", {
            "error": "File not found",
        })

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
    if not settings.ELASTIC:
        return render(request, "error.html", {
            "error": "ElasticSearch is not enabled and therefore it is "
                     "not possible to do a global search.",
        })

    if request.method == "GET":
        return render(request, "analysis/search.html")

    value = request.POST["search"]

    match_value = ".*".join(re.split("[^a-zA-Z0-9]+", value.lower()))

    r = settings.ELASTIC.search(
        index=settings.ELASTIC_INDEX + "-*",
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
        return render(request, "analysis/search_results.html", {
            "analyses": analyses,
            "term": request.POST["search"],
        })

    return render(request, "analysis/search.html", {
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
        return render(request, "error.html", {
            "error": "The specified analysis does not exist",
        })

    for analysis in analyses:
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

    return render(request, "success.html", {
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
        return render(request, "standalone_error.html", {
            "error": "The specified analysis does not exist",
        })

    try:
        if proto == "udp":
            connlist = conndata["network"]["udp"]
        else:
            connlist = conndata["network"]["tcp"]

        conns = filter(lambda i: (i["sport"], i["dport"], i["src"], i["dst"]) == (sport, dport, src, dst), connlist)
        stream = conns[0]
        offset = stream["offset"]
    except:
        return render(request, "standalone_error.html", {
            "error": "Could not find the requested stream",
        })

    try:
        fobj = fs.get(conndata["network"]["sorted_pcap_id"])
        setattr(fobj, "fileno", lambda: -1)
    except:
        return render(request, "standalone_error.html", {
            "error": "The required sorted PCAP does not exist",
        })

    packets = list(network.packets_for_stream(fobj, offset))
    # TODO: starting from django 1.7 we should use JsonResponse.
    return HttpResponse(json.dumps(packets), content_type="application/json")

def export_analysis(request, task_id):
    if request.method == "POST":
        return export(request, task_id)

    report = results_db.analysis.find_one(
        {"info.id": int(task_id)}, sort=[("_id", pymongo.DESCENDING)]
    )
    if not report:
        return render(request, "error.html", {
            "error": "The specified analysis does not exist",
        })

    if "analysis_path" not in report.get("info", {}):
        return render(request, "error.html", {
            "error": "The analysis was created before the export "
                     "functionality was integrated with Cuckoo and is "
                     "therefore not available for this task (in order to "
                     "export this analysis, please reprocess its report)."
        })

    analysis_path = report["info"]["analysis_path"]

    # Locate all directories/results available for this analysis.
    dirs, files = [], []
    for filename in os.listdir(analysis_path):
        path = os.path.join(analysis_path, filename)
        if os.path.isdir(path):
            dirs.append((filename, len(os.listdir(path))))
        else:
            files.append(filename)

    return render(request, "analysis/export.html", {
        "analysis": report,
        "dirs": dirs,
        "files": files,
    })

def json_default(obj):
    if isinstance(obj, datetime.datetime):
        if obj.utcoffset() is not None:
            obj = obj - obj.utcoffset()
        return calendar.timegm(obj.timetuple()) + obj.microsecond / 1000000.0
    raise TypeError("%r is not JSON serializable" % obj)

def export(request, task_id):
    taken_dirs = request.POST.getlist("dirs")
    taken_files = request.POST.getlist("files")
    if not taken_dirs and not taken_files:
        return render(request, "error.html", {
            "error": "Please select at least one directory or file to be exported."
        })

    report = results_db.analysis.find_one(
        {"info.id": int(task_id)}, sort=[("_id", pymongo.DESCENDING)]
    )
    if not report:
        return render(request, "error.html", {
            "error": "The specified analysis does not exist",
        })

    path = report["info"]["analysis_path"]

    # Creating an analysis.json file with basic information about this
    # analysis. This information serves as metadata when importing a task.
    analysis_path = os.path.join(path, "analysis.json")
    with open(analysis_path, "w") as outfile:
        report["target"].pop("file_id", None)
        metadata = {
            "info": report["info"],
            "target": report["target"],
        }
        json.dump(metadata, outfile, indent=4, default=json_default)

    f = StringIO()

    # Creates a zip file with the selected files and directories of the task.
    zf = zipfile.ZipFile(f, "w", zipfile.ZIP_DEFLATED, allowZip64=True)

    for dirname, subdirs, files in os.walk(path):
        if os.path.basename(dirname) == task_id:
            for filename in files:
                if filename in taken_files:
                    zf.write(os.path.join(dirname, filename), filename)
        if os.path.basename(dirname) in taken_dirs:
            for filename in files:
                zf.write(os.path.join(dirname, filename),
                         os.path.join(os.path.basename(dirname), filename))

    zf.close()

    response = HttpResponse(f.getvalue(), content_type="application/zip")
    response["Content-Disposition"] = "attachment; filename=%s.zip" % task_id
    return response

def import_analysis(request):
    if request.method == "GET":
        return render(request, "analysis/import.html")

    db = Database()
    task_ids = []

    for analysis in request.FILES.getlist("analyses"):
        if not analysis.size:
            return render(request, "error.html", {
                "error": "You uploaded an empty analysis.",
            })

        # if analysis.size > settings.MAX_UPLOAD_SIZE:
            # return render(request, "error.html", {
            #     "error": "You uploaded a file that exceeds that maximum allowed upload size.",
            # })

        if not analysis.name.endswith(".zip"):
            return render(request, "error.html", {
                "error": "You uploaded an analysis that wasn't a .zip.",
            })

        zf = zipfile.ZipFile(analysis)

        # As per Python documentation we have to make sure there are no
        # incorrect filenames.
        for filename in zf.namelist():
            if filename.startswith("/") or ".." in filename or ":" in filename:
                return render(request, "error.html", {
                    "error": "The zip file contains incorrect filenames, "
                             "please provide a legitimate .zip file.",
                })

        if "analysis.json" in zf.namelist():
            analysis_info = json.loads(zf.read("analysis.json"))
        elif "binary" in zf.namelist():
            analysis_info = {
                "target": {
                    "category": "file",
                },
            }
        else:
            analysis_info = {
                "target": {
                    "category": "url",
                    "url": "unknown",
                },
            }

        category = analysis_info["target"]["category"]
        info = analysis_info.get("info", {})

        if category == "file":
            binary = store_temp_file(zf.read("binary"), "binary")

            if os.path.isfile(binary):
                task_id = db.add_path(file_path=binary,
                                      package=info.get("package"),
                                      timeout=0,
                                      options=info.get("options"),
                                      priority=0,
                                      machine="",
                                      custom=info.get("custom"),
                                      memory=False,
                                      enforce_timeout=False,
                                      tags=info.get("tags"))
                if task_id:
                    task_ids.append(task_id)

        elif category == "url":
            url = analysis_info["target"]["url"]
            if not url:
                return render(request, "error.html", {
                    "error": "You specified an invalid URL!",
                })

            task_id = db.add_url(url=url,
                                 package=info.get("package"),
                                 timeout=0,
                                 options=info.get("options"),
                                 priority=0,
                                 machine="",
                                 custom=info.get("custom"),
                                 memory=False,
                                 enforce_timeout=False,
                                 tags=info.get("tags"))
            if task_id:
                task_ids.append(task_id)

        if not task_id:
            continue

        # Extract all of the files related to this analysis. This probably
        # requires some hacks depending on the user/group the Web
        # Interface is running under.
        analysis_path = os.path.join(
            CUCKOO_ROOT, "storage", "analyses", "%d" % task_id
        )

        if not os.path.exists(analysis_path):
            os.mkdir(analysis_path)

        zf.extractall(analysis_path)

        # We set this analysis as completed so that it will be processed
        # automatically (assuming process.py / process2.py is running).
        db.set_status(task_id, TASK_COMPLETED)

    if task_ids:
        return render(request, "submission/complete.html", {
            "tasks": task_ids,
            "baseurl": request.build_absolute_uri("/")[:-1],
        })

def reboot_analysis(request, task_id):
    task_id = Database().add_reboot(task_id=task_id)

    return render(request, "submission/reboot.html", {
        "task_id": task_id,
        "baseurl": request.build_absolute_uri("/")[:-1],
    })
