===========
Performance
===========

There are several ways to tune the Cuckoo performance

Processing
==========

Processing are the three steps after the malware executed in a VM. Those are

* processing of raw data
* signature matching
* reporting

Processing can take up to 30 minutes if the original raw log is large. This is caused by many API calls in that log. Several
steps will iterate through that API list which causes a slow down. There are several ways to mitigate the impact:

Evented signatures
------------------

Evented signatures have a common loop through the api calls. Use them wherever possible and either switch of the
old-style signatures with their own api-call loop or convert them to event based signatures

Reporting
---------

Reports that contain the API log will also iterate through the list. De-activate reports you do not need.
For automated environments switching off the html report will be a good choice.

Multi-Core processing
---------------------

By switching off processing ( *conf/cuckoo.conf*, ``process_results`` in ``[cuckoo]``) the processing step can
be done in a separate *utils/process.py* task running several process.

Ram-boost
---------

Ram boost can be switched on in the configuration (in *conf/cuckoo.conf* ``ram_boost`` in ``[processing]``).
This will keep the whole API list in Ram. Do that only if you have plenty of Ram (>20 GB for 8 VMs).