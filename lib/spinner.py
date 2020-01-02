# Modified Spinner class originally created by @Tagar


import itertools
import sys
import threading
import time


class Spinner:
    def __init__(self, message, delay=0.1):
        self.spinner = itertools.cycle(['-', '/', '|', '\\'])
        self.delay = delay
        self.busy = False
        self.spinner_visible = False
        self.message = message

    def write_next(self):
        with self._screen_lock:
            if not self.spinner_visible:
                sys.stdout.write('[' + next(self.spinner) + ']')
                sys.stdout.write(self.message)
                self.spinner_visible = True
                sys.stdout.flush()

    def remove_spinner(self, cleanup=False):
        with self._screen_lock:
            if self.spinner_visible:
                sys.stdout.write('\b' * len(self.message) + '\b' * 3)
                self.spinner_visible = False
                if cleanup:
                    sys.stdout.write(' ')
                    sys.stdout.write('\r')
                sys.stdout.flush()

    def spinner_task(self):
        while self.busy:
            self.write_next()
            time.sleep(self.delay)
            self.remove_spinner()

    def __enter__(self):
        if sys.stdout.isatty():
            self._screen_lock = threading.Lock()
            self.busy = True
            self.thread = threading.Thread(target=self.spinner_task)
            self.thread.start()

    def __exit__(self, exception, value, tb):
        if sys.stdout.isatty():
            self.busy = False
            self.remove_spinner(cleanup=True)
        else:
            sys.stdout.write('\r')
