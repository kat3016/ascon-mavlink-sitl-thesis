"""Shared helpers for the GCS measurement scripts."""
import os
import sys
import time

from pymavlink import mavutil

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mavcrypt import local_host  # noqa: E402

DEFAULT_CONN = f"udpout:{local_host()}:14560"  # secure_proxy.py GCS side


class Link:
    """pymavlink connection that keeps sending a GCS heartbeat (1 Hz).

    The heartbeat also lets secure_proxy.py learn this tool's address."""

    def __init__(self, conn, component):
        self.m = mavutil.mavlink_connection(conn, source_system=255, source_component=component)
        self.next_hb = 0.0
        self.target_system = 1
        self.target_component = 1

    def heartbeat_tick(self):
        now = time.monotonic()
        if now >= self.next_hb:
            self.m.mav.heartbeat_send(mavutil.mavlink.MAV_TYPE_GCS,
                                      mavutil.mavlink.MAV_AUTOPILOT_INVALID, 0, 0, 0)
            self.next_hb = now + 1.0

    def wait_vehicle(self, timeout):
        """Wait for a vehicle heartbeat, sending ours meanwhile."""
        t_end = time.monotonic() + timeout
        while time.monotonic() < t_end:
            self.heartbeat_tick()
            msg = self.m.recv_match(type="HEARTBEAT", blocking=True, timeout=0.5)
            if msg is not None and msg.get_srcSystem() != 255 and \
                    msg.type != mavutil.mavlink.MAV_TYPE_GCS:
                self.target_system = msg.get_srcSystem()
                self.target_component = msg.get_srcComponent()
                return True
        return False
