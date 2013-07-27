from pymongo.connection import Connection

db = Connection().cuckoo

# Set an unique index on stored files, to avoid duplicates.
#db.fs.files.ensure_index("sha256", unique=True, name="sha256_unique")

# Indexes on search fields.
#db.analysis.ensure_index("target.file.name", name="target_file_name", background=True)
#db.analysis.ensure_index("target.file.type", name="target_file_type", background=True)
#db.analysis.ensure_index("target.file.ssdeep", name="target_file_ssdeep", sparse=True, background=True)
#db.analysis.ensure_index("target.file.crc32", name="target_file_crc32", background=True)
#db.analysis.ensure_index("behavior.summary.files", name="behavior_summary_files", sparse=True, background=True)
#db.analysis.ensure_index("behavior.summary.keys", name="behavior_summary_keys", sparse=True, background=True)
#db.analysis.ensure_index("behavior.summary.mutexes", name="behavior_summary_mutexes", sparse=True, background=True)
#db.analysis.ensure_index("network.domains.domain", name="network_domains_domain", sparse=True, background=True)
#db.analysis.ensure_index("network.hosts", name="network_hosts", sparse=True, background=True)
