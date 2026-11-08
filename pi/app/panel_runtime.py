"""Small concurrency helpers for a responsive control panel."""
import queue
import threading
import time


class ProbeScope:
    """Cancel competing protocol checks by closing their local proxy processes."""
    def __init__(self):
        self.cancelled = threading.Event()
        self.lock = threading.Lock()
        self.processes = set()

    def register(self, process):
        with self.lock:
            if not self.cancelled.is_set():
                self.processes.add(process)
                return
        self._terminate(process)

    def discard(self, process):
        with self.lock:
            self.processes.discard(process)

    @staticmethod
    def _terminate(process):
        try:
            process.terminate()
        except OSError:
            pass

    def cancel(self):
        with self.lock:
            self.cancelled.set()
            processes = tuple(self.processes)
        for process in processes:
            self._terminate(process)


def first_success(candidates, check, timeout=30):
    """Return first working candidate, not the slowest failed alternative."""
    scope, results = ProbeScope(), queue.Queue()
    errors = {}

    def worker(index, outbound):
        try:
            info, error = check(outbound, scope)
        except Exception:
            info, error = None, 'ошибка проверки'
        results.put((index, info, error))

    for index, (_, outbound) in enumerate(candidates):
        threading.Thread(target=worker, args=(index, outbound), daemon=True).start()
    end = time.monotonic() + timeout
    try:
        for _ in candidates:
            try:
                index, info, error = results.get(timeout=max(0, end - time.monotonic()))
            except queue.Empty:
                break
            if info:
                kind, outbound = candidates[index]
                return kind, outbound, info, []
            errors[index] = error or 'через прокси нет ответа'
        return None, None, None, [
            '%s: %s' % (kind, errors.get(index, 'время проверки истекло'))
            for index, (kind, _) in enumerate(candidates)]
    finally:
        scope.cancel()
