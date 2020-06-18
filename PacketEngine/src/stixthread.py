"""
Copyright 2019 Southern California Edison
Copyright 2019 Pacific Gas and Electric Company

ALL RIGHTS RESERVED
"""
import json
import threading
from queue import Queue

import requests

from packetengine import settings


class STIXPoster(threading.Thread):
    def __init__(self, id: int, queue: Queue):
        super().__init__()
        self.q = queue
        self.running = False
        self.id = id

    def run(self):
        self.running = True
        while self.running:
            observed = self.q.get()
            try:

                r = requests.post(settings.BASE_URL + ':' + settings.API_PORT + '/api/stix-object/',
                                  data=json.dumps(json.loads(str(observed))), verify=False,
                                  headers={'content-type': 'application/json'}, timeout=10)

                if r.status_code != 201:
                    print("Error posting:")
                    print(r)
                    print(r.content)
                    # raise RuntimeError(r)

                f = open("data/test.json", "w")
                f.write(json.dumps(json.loads(str(observed))))
                f.close()
            except Exception as e:
                print(f'{e}')
            self.q.task_done()
            print(f'thread-{self.id} done. Queue length: {self.q.qsize()}\n')
        self.stop()

    def stop(self):
        print(f'thread-{self.id} quitting')
        self.running = False
