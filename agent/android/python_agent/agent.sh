export PYTHONHOME=/data/local/python
export PYTHONPATH=/data/local/python/extras/python:/data/local/python/lib/python2.7/lib-dynload:/data/local/python/lib/python2.7
export PATH=$PYTHONHOME/bin:$PATH
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/data/local/python/lib:/data/local/python/lib/python2.7/lib-dynload
cd /data/local/
/data/local/python/bin/python /data/local/agent.py