import multiprocessing

def dispatch(func, args=(), kwargs={}, timeout=60, process=True):
    """Dispatch a function call to a separate process or thread to execute with
    a maximum provided timeout. Note that in almost all occurrences a separate
    process should be used as otherwise we might end up with out-of-order
    locking mechanism instances, resulting in undefined behavior later on."""
    def worker(conn, func, *args, **kwargs):
        conn.send(func(*args, **kwargs))
        conn.close()

    if not isinstance(args, tuple) or not isinstance(kwargs, dict):
        raise RuntimeError("args must be a tuple and kwargs a dict")

    if not process:
        raise RuntimeError("no support yet for dispatch(process=False)")

    parent, child = multiprocessing.Pipe()
    p = multiprocessing.Process(
        target=worker, args=(child, func) + args, kwargs=kwargs
    )
    p.start()
    p.join(timeout)
    if p.is_alive():
        p.terminate()
        parent.close()
        return

    ret = parent.recv()
    parent.close()
    return ret

