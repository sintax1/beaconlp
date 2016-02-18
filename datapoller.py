#!/usr/bin/env python

from __future__ import print_function
import threading
import time

import api


class DataPoller(object):
    """Class for polling for data from the BLiP controller

        Beacon Filters and Tasking will be received and stored
        locally and used to process each packet seen.
    """

    def __init__(
        self, interval=5, beacon_filters=None,
            task_queue=None, logger=print):
        """ Constructor

        :type interval: int
        :param interval: Check interval (seconds)
        :type beacon_filters: dict
        :param beacon_filters: Dictionary of {beacon filter -> beacon handler}
        :type task_queue: dict
        :param task_queue: Dictionary of Implant tasks {uuid -> tasks}
        """
        self.interval = interval
        self.beacon_filters = beacon_filters
        self.task_queue = task_queue
        self.running = True
        self.logger = logger

    def check_beacon_filters(self):
        """Get Beacon Filters from the controller and update the local list"""

        self.logger("Checking for new Beacon filters")

        try:
            new_beacon_filters = api.get_beacon_filters()['result']
            self.beacon_filters.beacon_update(new_beacon_filters)
        except (TypeError, KeyError):
            self.logger("No Beacon Filters received")
            self.logger("Beacon filter info received: %s" % new_beacon_filters)

    def check_tasks(self):
        """Get Tasks from the controller and update the queue"""

        self.logger("Checking for new Tasks")

        implants = api.get_implants()

        try:
            implants = implants['result']

            for implant in implants:
                uuid = implant['uuid']

                tasks = implant['all_tasks']
                for task in tasks:
                    if uuid not in self.task_queue.keys():
                        self.task_queue[uuid] = set()
                    self.task_queue[uuid].add(task)

        except (TypeError, KeyError):
            self.logger("No Tasks received")
            self.logger("Implant info received: %s" % implants)

    def loop(self):
        """Run forever"""
        while self.running:
            self.check_tasks()
            self.check_beacon_filters()
            time.sleep(self.interval)

    def stop(self):
        self.running = False
        self.thread.join()

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self.loop, args=())
        self.thread.daemon = True
        self.thread.start()

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(prog='Lp')
    parser.add_argument("-v", "--verbose", help="increase output verbosity",
                        action="store_true", default=False)
    parser.add_argument("-d", "--daemon", help="run in background (daemonize)",
                        choices=['start', 'stop', 'restart'],
                        default=False)
    args = parser.parse_args()

    dp = DataPoller()
    dp.verbose = args.verbose

    if args.daemon == 'start':
        print("start")
        dp.start()
    elif args.daemon == 'stop':
        print("stop")
        dp.stop()
    elif args.daemon == 'restart':
        print("restart")
        dp.restart()
    else:
        print("loop")
        dp.loop()
