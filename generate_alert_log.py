"""Realistic Oracle alert log simulator.

Generates a synthetic Oracle 19c alert log (Oracle E-Business Suite flavour) with
realistic daily activity and multi-step incidents, plus a ground-truth CSV of every
incident written, so you can test that your parser finds exactly what it should.

What makes it realistic:
  - Daily rhythm: busier redo log switches in business hours, nightly RMAN autobackup,
    maintenance windows, auto-extend resizes, interval partition messages.
  - Incidents that unfold over time, not just random lines:
      * recovery area fills -> archiver stops -> ORA-16038 retries -> ORA-00257 -> DBA fix
      * tablespace full -> repeated ORA-1653 -> DBA adds datafile -> errors stop
      * background process dies -> PMON terminates instance -> crash recovery on restart
  - Real alert log quirks: unpadded codes (ORA-1653), error stacks (ORA-06512, ORA-01110),
    "ORA-60" references inside messages, TNS-only blocks that are not ORA errors,
    noise such as "opiodr aborting process ... ORA-609".
  - Timestamps in your time zone with correct daylight saving changes, in the 12c+
    ISO format or the legacy 11g format.

Usage:
    python generate_alert_log.py                      # 30 days, America/Toronto
    python generate_alert_log.py --days 7 --seed 1
    python generate_alert_log.py --size-mb 10         # keep going until ~10 MB
    python generate_alert_log.py --format legacy      # 11g style timestamps
    python generate_alert_log.py --error-rate 2       # twice as many incidents
"""

import argparse
import bisect
import csv
import math
import random
import re
import sys
from collections import Counter
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

ORA_RE = re.compile(r"ORA-(\d{3,5})\b")
UTC = timezone.utc


def norm(code) -> str:
    """'1653', 1653 or 'ORA-1653' -> 'ORA-01653'."""
    return f"ORA-{int(str(code).replace('ORA-', '')):05d}"


@dataclass
class Entry:
    when: datetime                      # UTC, timezone-aware
    order: int                          # tie-breaker to keep insertion order
    text: str
    scenario: str = ""
    codes: list = field(default_factory=list)   # first = primary incident code
    routine: bool = False               # normal activity, suppressed while instance is down
    lifecycle: bool = False             # startup/shutdown/crash lines, never suppressed
    forced: bool = False                # guaranteed-coverage incident, never suppressed


# ---------------------------------------------------------------------------
# Static Oracle EBS flavour
# ---------------------------------------------------------------------------

DATAFILES = [
    (5, "apps_ts_tx_data01.dbf"), (6, "apps_ts_tx_idx01.dbf"), (7, "users01.dbf"),
    (8, "apps_ts_media01.dbf"), (9, "ar_data01.dbf"), (10, "apps_ts_tx_data02.dbf"),
    (11, "apps_ts_tx_idx02.dbf"), (12, "sysaux01.dbf"),
]
TABLE_SEGMENTS = [
    ("APPS_TS_TX_DATA", "AR", "RA_CUSTOMER_TRX_LINES_ALL"),
    ("APPS_TS_TX_DATA", "ONT", "OE_ORDER_LINES_ALL"),
    ("APPS_TS_TX_DATA", "GL", "GL_JE_LINES"),
    ("APPS_TS_TX_DATA", "XXCUST", "XX_ORDER_STAGING"),
    ("SYSAUX", "SYS", "WRH$_ACTIVE_SESSION_HISTORY"),
]
INDEX_SEGMENTS = [
    ("APPS_TS_TX_IDX", "ONT", "OE_ORDER_LINES_N1"),
    ("APPS_TS_TX_IDX", "GL", "GL_JE_LINES_N1"),
    ("APPS_TS_TX_IDX", "AR", "RA_CUSTOMER_TRX_LINES_N2"),
]
PARTITION_SEGMENTS = [
    ("AR_DATA", "AR", "AR_DISTRIBUTIONS_ALL", "P2026_10"),
    ("APPS_TS_TX_DATA", "XLA", "XLA_AE_LINES", "AR"),
]
LOB_SEGMENTS = [("APPS_TS_MEDIA", "APPLSYS", "SYS_LOB0000034032C00004$$")]
LONG_QUERIES = [
    "SELECT /*+ PARALLEL(8) */ CODE_COMBINATION_ID, SUM(ACCOUNTED_DR) FROM GL.GL_JE_LINES "
    "WHERE PERIOD_NAME = :B1 GROUP BY CODE_COMBINATION_ID",
    "SELECT H.HEADER_ID, L.LINE_ID, L.ORDERED_QUANTITY FROM ONT.OE_ORDER_HEADERS_ALL H, "
    "ONT.OE_ORDER_LINES_ALL L WHERE H.HEADER_ID = L.HEADER_ID AND H.CREATION_DATE > :B1",
    "SELECT CUSTOMER_TRX_ID, SUM(EXTENDED_AMOUNT) FROM AR.RA_CUSTOMER_TRX_LINES_ALL "
    "GROUP BY CUSTOMER_TRX_ID",
]
ORA600_ARGS = ["[kdsgrp1]", "[kcbz_check_objd_typ_3]", "[17147], [0x7F411C]",
               "[ktspgetnextlmbblock-1]", "[qertbFetchByRowID]", "[4193], [12517], [12521]"]
ORA7445_FUNCS = ["kghfrf()+92", "qerixtFetch()+1205", "kkqsGetLeafs()+341", "evaopn2()+1290"]
SQLID_CHARS = "0123456789abcdfghjkmnpqrstuvwxyz"


class AlertLogSimulator:
    def __init__(self, db: str, tz: str, fmt: str, rng: random.Random, error_rate: float):
        self.db = db.upper()
        self.zone = ZoneInfo(tz)
        self.fmt = fmt
        self.rng = rng
        self.error_rate = error_rate
        self.oh = "/u01/app/oracle/product/19.0.0/dbhome_1"
        self.diag = f"/u01/app/oracle/diag/rdbms/{self.db.lower()}/{self.db}"
        self.oradata = f"/u02/oradata/{self.db}"
        self.fra = f"/u03/fra/{self.db}"
        self.entries: list[Entry] = []
        self.downtime: list[tuple[datetime, datetime]] = []
        self.archiver_stopped: list[tuple[datetime, datetime]] = []
        self.order = 0
        self.seq0 = rng.randint(40000, 46000)
        self.switch_times: list[datetime] = []
        self.scn0 = rng.randint(10**10, 9 * 10**10)
        self.t0: datetime | None = None
        self.archive_entry = rng.randint(80000, 99000)
        self.incident_id = rng.randint(40000, 60000)
        self.pids: dict[str, int] = {}
        self.new_pids()

    # -- helpers ------------------------------------------------------------
    def new_pids(self):
        procs = ["pmon", "clmn", "psp0", "vktm", "gen0", "dbw0", "lgwr", "ckpt", "smon",
                 "reco", "mmon", "mmnl", "arc0", "arc1", "arc2", "arc3", "tt00", "cjq0"]
        base = self.rng.randint(1100, 30000)
        self.pids = {p: base + i * self.rng.randint(1, 4) for i, p in enumerate(procs)}

    def pid(self, proc: str) -> int:
        if proc not in self.pids:            # foreground or job processes get fresh pids
            return self.rng.randint(2000, 65000)
        return self.pids[proc]

    def trace(self, proc: str, pid: int | None = None) -> str:
        return f"{self.diag}/trace/{self.db}_{proc}_{pid or self.pid(proc)}.trc"

    def next_incident(self) -> int:
        self.incident_id += self.rng.randint(1, 40)
        return self.incident_id

    def datafile(self):
        num, name = self.rng.choice(DATAFILES)
        return num, f"{self.oradata}/{name}"

    def redo(self, group: int, member: str = "a") -> str:
        return f"{self.oradata}/redo0{group}{member}.log"

    def seq_at(self, t: datetime) -> int:
        """Current redo log sequence at time t."""
        return self.seq0 + bisect.bisect_right(self.switch_times, t)

    def scn_at(self, t: datetime) -> int:
        """SCN grows steadily with time, so values always increase through the log."""
        return self.scn0 + int((t - self.t0).total_seconds() * 2700)

    def group_at(self, t: datetime) -> int:
        return (self.seq_at(t) % 4) + 1

    def add(self, when: datetime, text: str, scenario: str = "", codes=None, jitter=True, **flags):
        self.order += 1
        if jitter:
            when = when + timedelta(microseconds=self.rng.randint(0, 999_999))
        self.entries.append(Entry(when, self.order, text, scenario,
                                  [norm(c) for c in (codes or [])], **flags))

    def ts_text(self, when: datetime) -> str:
        local = when.astimezone(self.zone)
        if self.fmt == "legacy":
            return local.strftime("%a %b %d %H:%M:%S %Y")
        return local.isoformat(timespec="microseconds")

    def local_midnight_utc(self, day: date) -> datetime:
        return datetime(day.year, day.month, day.day, tzinfo=self.zone).astimezone(UTC)

    def at_local(self, day: date, hour: float) -> datetime:
        h, rem = divmod(hour * 3600, 3600)
        m, s = divmod(rem, 60)
        local = datetime(day.year, day.month, day.day, int(h), int(m), int(s), tzinfo=self.zone)
        return local.astimezone(UTC)

    def random_time(self, day: date, profile: str = "any") -> datetime:
        if profile == "business":
            hour = min(max(self.rng.gauss(12.5, 2.8), 7.5), 19.5)
        elif profile == "night":
            hour = self.rng.uniform(0.2, 5.8)
        else:
            hour = self.rng.uniform(0, 23.99)
        return self.at_local(day, hour)

    def poisson(self, lam: float) -> int:
        if lam <= 0:
            return 0
        limit, k, p = math.exp(-lam), 0, 1.0
        while True:
            p *= self.rng.random()
            if p <= limit:
                return k
            k += 1

    # -- routine activity ---------------------------------------------------
    def log_switch(self, t: datetime, busy: bool):
        old_seq = self.seq_at(t)
        group = (old_seq % 4) + 1
        if busy and self.rng.random() < 0.04:
            self.add(t - timedelta(seconds=self.rng.randint(5, 40)),
                     f"Thread 1 cannot allocate new log, sequence {old_seq + 1}\n"
                     f"Checkpoint not complete\n"
                     f"  Current log# {group} seq# {old_seq} mem# 0: {self.redo(group)}",
                     routine=True)
        self.switch_times.append(t)
        new_seq = old_seq + 1
        nxt = (group % 4) + 1
        self.add(t, f"Thread 1 advanced to log sequence {new_seq} (LGWR switch),  "
                    f"current SCN: {self.scn_at(t)}\n"
                    f"  Current log# {nxt} seq# {new_seq} mem# 0: {self.redo(nxt)}\n"
                    f"  Current log# {nxt} seq# {new_seq} mem# 1: {self.redo(nxt, 'b')}",
                 routine=True)
        self.archive_entry += 1
        arc = self.rng.choice(["arc0", "arc1", "arc2", "arc3"])
        self.add(t + timedelta(seconds=self.rng.randint(3, 50)),
                 f"{arc.upper()} (PID:{self.pid(arc)}): Archived Log entry {self.archive_entry} added for "
                 f"B-1180943236.T-1.S-{old_seq} ID 0x8a4d5c1e LAD:1",
                 routine=True)

    def routine_day(self, day: date):
        start, end = self.local_midnight_utc(day), self.local_midnight_utc(day + timedelta(days=1))
        weekday = day.weekday() < 5
        t = start + timedelta(minutes=self.rng.uniform(5, 40))
        while t < end:
            hour = t.astimezone(self.zone).hour
            busy = weekday and 8 <= hour < 19
            self.log_switch(t, busy)
            t += timedelta(minutes=self.rng.uniform(10, 28) if busy else self.rng.uniform(35, 95))

        self.add(self.at_local(day, 0.01),
                 f"TABLE SYS.WRI$_OPTSTAT_HISTHEAD_HISTORY: ADDED INTERVAL PARTITION SYS_P{self.rng.randint(1000, 9999)} "
                 f"({self.rng.randint(40000, 49999)}) VALUES LESS THAN (TO_DATE(' "
                 f"{(day + timedelta(days=1)).isoformat()} 00:00:00', 'SYYYY-MM-DD HH24:MI:SS', "
                 f"'NLS_CALENDAR=GREGORIAN'))", routine=True)
        self.add(self.at_local(day, 1.5 + self.rng.uniform(0, 0.3)),
                 f"Starting control autobackup\nControl autobackup written to DISK device\n\n"
                 f"handle '{self.fra}/autobackup/{day.strftime('%Y_%m_%d')}/o1_mf_s_{self.rng.randint(10**9, 2 * 10**9)}_.bkp'",
                 routine=True)
        if weekday or day.weekday() == 5:
            self.add(self.at_local(day, 2.0),
                     "Closing scheduler window\nRestoring Resource Manager plan DEFAULT_PLAN via scheduler window\n"
                     "Setting Resource Manager plan DEFAULT_PLAN via parameter", routine=True)
        if weekday:
            self.add(self.at_local(day, 22.0),
                     "Setting Resource Manager plan SCHEDULER[0x4D52]:DEFAULT_MAINTENANCE_PLAN via scheduler window\n"
                     "Setting Resource Manager plan DEFAULT_MAINTENANCE_PLAN via parameter", routine=True)
        for _ in range(self.poisson(3)):
            num, _path = self.datafile()
            old = self.rng.randint(20, 31) * 1024 * 1024
            self.add(self.random_time(day),
                     f"Resize operation completed for file# {num}, fname {_path}, "
                     f"old size {old}K, new size {old + 102400}K", routine=True)
        for _ in range(self.poisson(1.2 * self.error_rate)):
            self.add(self.random_time(day, "business"),
                     f"opiodr aborting process unknown ospid ({self.rng.randint(2000, 65000)}) as a result of ORA-609",
                     "client_disconnect", [609])
        for _ in range(self.poisson(1.5)):
            self.fatal_ni_block(self.random_time(day, "business"))
        # Monthly patching restart: first Sunday of the month at 03:00
        if day.weekday() == 6 and day.day <= 7:
            down = self.at_local(day, 3.0)
            self.shutdown(down, "immediate")
            self.startup(down + timedelta(minutes=self.rng.uniform(15, 40)), crash=False, down_from=down)

    def fatal_ni_block(self, t: datetime):
        """Listener/network noise. Contains TNS- codes only, which are NOT ORA errors."""
        local = t.astimezone(self.zone)
        self.add(t, "\n***********************************************************************\n\n"
                    "Fatal NI connect error 12537, connecting to:\n (LOCAL=NO)\n\n"
                    "  VERSION INFORMATION:\n\tTNS for Linux: Version 19.0.0.0.0 - Production\n"
                    "\tTCP/IP NT Protocol Adapter for Linux: Version 19.0.0.0.0 - Production\n"
                    f"  Version 19.24.0.0.0\n  Time: {local.strftime('%d-%b-%Y %H:%M:%S').upper()}\n"
                    "  Tracing not turned on.\n  Tns error struct:\n    ns main err code: 12537\n\n"
                    "TNS-12537: TNS:connection closed\n    ns secondary err code: 12560\n"
                    "    nt main err code: 0\n    nt secondary err code: 0\n    nt OS err code: 0\n"
                    f"  Client address: (ADDRESS=(PROTOCOL=tcp)(HOST=10.20.{self.rng.randint(1, 254)}."
                    f"{self.rng.randint(1, 254)})(PORT={self.rng.randint(30000, 65000)}))",
                 routine=True)

    # -- lifecycle ------------------------------------------------------------
    def shutdown(self, t: datetime, mode: str):
        pid = self.rng.randint(2000, 65000)
        steps = [
            f"Shutting down ORACLE instance ({mode}) (OS id: {pid})",
            "Shutting down instance: further logons disabled",
            "Stopping background process CJQ0",
            "Stopping background process MMNL\nStopping background process MMON",
            "License high water mark = 1187",
            "alter database close normal\nstopping change tracking",
            "Shutting down archive processes\nArchiving is disabled",
            "Completed: alter database close normal\nalter database dismount\nCompleted: alter database dismount",
            f"Instance shutdown complete (OS id: {pid})",
        ]
        self.add_sequence(t, steps)

    def add_sequence(self, t: datetime, steps: list[str]) -> datetime:
        """Write lifecycle steps in strict order, a little time apart."""
        for s in steps:
            self.add(t, s, jitter=False, lifecycle=True)
            t += timedelta(seconds=self.rng.uniform(0.4, 3.5))
        return t

    def startup(self, t: datetime, crash: bool, down_from: datetime | None = None):
        if self.t0 is None:
            self.t0 = t
        self.new_pids()
        seq = self.seq_at(t)
        group = (seq % 4) + 1
        params = (f"Using parameter settings in server-side spfile {self.oh}/dbs/spfile{self.db}.ora\n"
                  "System parameters with non-default values:\n"
                  "  processes                = 1500\n  sessions                 = 2272\n"
                  "  sga_target               = 32G\n  pga_aggregate_target     = 8G\n"
                  "  db_block_size            = 8192\n  compatible               = \"19.0.0\"\n"
                  f"  db_recovery_file_dest    = \"/u03/fra\"\n  db_recovery_file_dest_size= 200G\n"
                  f"  undo_tablespace          = \"UNDOTBS1\"\n  db_name                  = \"{self.db}\"")
        steps = [
            f"Starting ORACLE instance (normal) (OS id: {self.pids['pmon'] - 1})",
            "Oracle Database 19c Enterprise Edition Release 19.0.0.0.0 - Production\nVersion 19.24.0.0.0.",
            params,
            "\n".join(f"{p.upper()} started with pid={i + 2}, OS id={self.pids[p]}"
                      for i, p in enumerate(["pmon", "clmn", "psp0", "vktm", "gen0"])),
            "\n".join(f"{p.upper()} started with pid={i + 12}, OS id={self.pids[p]}"
                      for i, p in enumerate(["dbw0", "lgwr", "ckpt", "smon", "reco", "mmon", "mmnl"])),
            "ALTER DATABASE   MOUNT",
            "Completed: ALTER DATABASE   MOUNT",
            "ALTER DATABASE OPEN",
        ]
        if crash:
            steps.append(
                "Beginning crash recovery of 1 threads\n parallel recovery started with 7 processes\n"
                f"Started redo scan\nCompleted redo scan\n read {self.rng.randint(2000, 90000)} KB redo, "
                f"{self.rng.randint(300, 9000)} data blocks need recovery")
            steps.append(f"Completed crash recovery at\n Thread 1: RBA {seq}.{self.rng.randint(1000, 9999)}.16, "
                         f"nab {self.rng.randint(1000, 9999)}, scn 0x{self.scn_at(t):016x}")
        steps += [
            f"Thread 1 opened at log sequence {seq}\n"
            f"  Current log# {group} seq# {seq} mem# 0: {self.redo(group)}\n"
            "Successful open of redo thread 1",
            "SMON: enabling cache recovery",
            "Starting background process CJQ0\nCJQ0 started with pid=52, OS id=" + str(self.pids["cjq0"]),
            "Completed: ALTER DATABASE OPEN",
        ]
        opened = self.add_sequence(t, steps)
        if down_from is not None:
            self.downtime.append((down_from, opened))

    # -- incident scenarios ---------------------------------------------------
    # Each scenario writes one or more timestamped blocks. `codes` lists the ORA
    # codes in each block in order; the first one is the incident.

    def sc_internal_600(self, t, f):
        proc, pid = "ora", self.rng.randint(2000, 65000)
        inc = self.next_incident()
        self.add(t, f"Errors in file {self.trace(proc, pid)}  (incident={inc}):\n"
                    f"ORA-00600: internal error code, arguments: {self.rng.choice(ORA600_ARGS)}, [], [], [], [], [], [], [], []\n"
                    f"Incident details in: {self.diag}/incident/incdir_{inc}/{self.db}_{proc}_{pid}_i{inc}.trc\n"
                    "Use ADRCI or Support Workbench to package the incident.\n"
                    "See Note 411.1 at My Oracle Support for error and packaging details.",
                 "internal_error", [600], forced=f)
        self.add(t + timedelta(seconds=self.rng.randint(1, 5)),
                 f"Dumping diagnostic data in directory=[cdmp_{t.astimezone(self.zone).strftime('%Y%m%d%H%M%S')}], "
                 f"requested by (instance=1, osid={pid}), summary=[incident={inc}].", routine=True)

    def sc_internal_7445(self, t, f):
        pid, inc = self.rng.randint(2000, 65000), self.next_incident()
        func = self.rng.choice(ORA7445_FUNCS)
        pc = f"0x{self.rng.randint(0x1000000, 0xFFFFFFF):X}"
        self.add(t, f"Exception [type: SIGSEGV, Address not mapped to object] [ADDR:0x0] [PC:{pc}, {func}] "
                    "[flags: 0x0, count: 1]\n"
                    f"Errors in file {self.trace('ora', pid)}  (incident={inc}):\n"
                    f"ORA-07445: exception encountered: core dump [{func}] [SIGSEGV] [ADDR:0x0] [PC:{pc}] "
                    "[Address not mapped to object] []\n"
                    f"Incident details in: {self.diag}/incident/incdir_{inc}/{self.db}_ora_{pid}_i{inc}.trc",
                 "internal_error", [7445], forced=f)

    def sc_fra_full(self, t, f):
        arc = self.rng.choice(["arc1", "arc2"])
        seq = self.seq_at(t)
        group = (seq % 4) + 1
        limit = 200 * 1024**3
        self.add(t, f"Errors in file {self.trace(arc)}:\n"
                    "ORA-19809: limit exceeded for recovery files\n"
                    f"ORA-19804: cannot reclaim {self.rng.randint(1, 50) * 1048576} bytes disk space from {limit} bytes limit\n"
                    f"{arc.upper()} (PID:{self.pid(arc)}): Error 19809 Creating archive log file to "
                    f"'{self.fra}/archivelog/{t.astimezone(self.zone).strftime('%Y_%m_%d')}/o1_mf_1_{seq}_.arc'",
                 "recovery_area_full", [19809, 19804], forced=f)
        self.add(t + timedelta(seconds=2),
                 f"{arc.upper()} (PID:{self.pid(arc)}): Archival stopped, error occurred. Will continue retrying\n"
                 f"ORACLE Instance {self.db} - Archival Error", "recovery_area_full")
        duration = self.rng.uniform(20, 120)
        m = self.rng.uniform(2, 6)
        while m < duration:
            when = t + timedelta(minutes=m)
            self.add(when, f"Errors in file {self.trace(arc)}:\n"
                           f"ORA-16038: log {group} sequence# {seq} cannot be archived\n"
                           "ORA-19809: limit exceeded for recovery files\n"
                           f"ORA-00312: online log {group} thread 1: '{self.redo(group)}'",
                     "recovery_area_full", [16038, 19809, 312], forced=f)
            if self.rng.random() < 0.6:
                self.add(when + timedelta(seconds=self.rng.randint(5, 50)),
                         f"Errors in file {self.trace('ora')}:\n"
                         "ORA-00257: Archiver error. Connect AS SYSDBA only until resolved.",
                         "recovery_area_full", [257], forced=f)
            m += self.rng.uniform(3, 9)
        fix = t + timedelta(minutes=duration + 1)
        self.archiver_stopped.append((t, fix + timedelta(seconds=21)))
        self.add(fix, "ALTER SYSTEM SET db_recovery_file_dest_size='300G' SCOPE=BOTH;", "recovery_area_full")
        self.add(fix + timedelta(seconds=20),
                 f"{arc.upper()} (PID:{self.pid(arc)}): Archiver process freed from errors. No longer stopped",
                 "recovery_area_full")

    def sc_space(self, t, f, kind: str):
        if kind == "table":
            ts, owner, seg = self.rng.choice(TABLE_SEGMENTS)
            msg, code = f"ORA-1653: unable to extend table {owner}.{seg} by {{n}} in tablespace {ts}", 1653
        elif kind == "index":
            ts, owner, seg = self.rng.choice(INDEX_SEGMENTS)
            msg, code = f"ORA-1654: unable to extend index {owner}.{seg} by {{n}} in tablespace {ts}", 1654
        elif kind == "partition":
            ts, owner, seg, part = self.rng.choice(PARTITION_SEGMENTS)
            msg, code = f"ORA-1688: unable to extend table {owner}.{seg} partition {part} by {{n}} in tablespace {ts}", 1688
        else:
            ts, owner, seg = self.rng.choice(LOB_SEGMENTS)
            msg, code = f"ORA-1691: unable to extend lobsegment {owner}.{seg} by {{n}} in tablespace {ts}", 1691
        duration = self.rng.uniform(15, 120)
        m = 0.0
        while m < duration:
            self.add(t + timedelta(minutes=m), msg.format(n=self.rng.choice([128, 1024, 8192])),
                     f"tablespace_full_{kind}", [code], forced=f)
            m += self.rng.uniform(1, 12)
        fix = t + timedelta(minutes=duration + 2)
        nxt = self.rng.randint(3, 9)
        stmt = (f"ALTER TABLESPACE {ts} ADD DATAFILE '{self.oradata}/{ts.lower()}0{nxt}.dbf' "
                "SIZE 30G AUTOEXTEND ON NEXT 1G MAXSIZE UNLIMITED")
        self.add(fix, stmt, f"tablespace_full_{kind}")
        self.add(fix + timedelta(seconds=self.rng.randint(20, 90)), f"Completed: {stmt}", f"tablespace_full_{kind}")

    def sc_temp_full(self, t, f):
        for i in range(self.rng.randint(1, 5)):
            self.add(t + timedelta(minutes=i * self.rng.uniform(0.5, 5)),
                     "ORA-1652: unable to extend temp segment by 128 in tablespace                 TEMP",
                     "temp_full", [1652], forced=f)

    def sc_undo_extend(self, t, f):
        self.add(t, f"Errors in file {self.trace('ora')}:\n"
                    "ORA-30036: unable to extend segment by 8 in undo tablespace 'UNDOTBS1'",
                 "undo_full", [30036], forced=f)

    def sc_snapshot_too_old(self, t, f):
        sqlid = "".join(self.rng.choice(SQLID_CHARS) for _ in range(13))
        self.add(t, f"ORA-01555 caused by SQL statement below (SQL ID: {sqlid}, "
                    f"Query Duration={self.rng.randint(900, 14000)} sec, SCN: 0x{self.scn_at(t):016x}):\n"
                    f"{self.rng.choice(LONG_QUERIES)}",
                 "snapshot_too_old", [1555], forced=f)

    def sc_shared_pool(self, t, f):
        for i in range(self.rng.randint(1, 4)):
            self.add(t + timedelta(seconds=i * self.rng.randint(10, 120)),
                     f"Errors in file {self.trace('ora')}:\n"
                     f"ORA-04031: unable to allocate {self.rng.choice([4160, 32, 65560])} bytes of shared memory "
                     f"(\"shared pool\",\"unknown object\",\"sga heap({self.rng.randint(1, 4)},0)\",\"KGLH0^{self.rng.randint(10**7, 10**8):x}\")",
                     "shared_pool_exhausted", [4031], forced=f)

    def sc_pga(self, t, f):
        pid, inc = self.rng.randint(2000, 65000), self.next_incident()
        self.add(t, f"Errors in file {self.trace('ora', pid)}  (incident={inc}):\n"
                    "ORA-04030: out of process memory when trying to allocate 16328 bytes (koh-kghu sessi,pl/sql vc2)\n"
                    f"Incident details in: {self.diag}/incident/incdir_{inc}/{self.db}_ora_{pid}_i{inc}.trc",
                 "process_memory", [4030], forced=f)

    def sc_corruption(self, t, f):
        num, path = self.datafile()
        block = self.rng.randint(1000, 4_000_000)
        dba = (num << 22) | block
        inc = self.next_incident()
        tr = self.trace("ora")
        self.add(t, f"Hex dump of (file {num}, block {block}) in trace file {tr}\n"
                    f"Corrupt block relative dba: 0x{dba:08x} (file {num}, block {block})\n"
                    "Bad check value found during multiblock buffer read\nData in bad block:\n"
                    f" type: 6 format: 2 rdba: 0x{dba:08x}\n"
                    f" last change scn: 0x0000.{self.scn_at(t) % 2**32:08x} seq: 0x1 flg: 0x06\n"
                    f"Reading datafile '{path}' for corrupt data at rdba: 0x{dba:08x} (file {num}, block {block})\n"
                    f"Reread (file {num}, block {block}) found same corrupt data (no logical check)\n"
                    f"Errors in file {tr}  (incident={inc}):\n"
                    f"ORA-01578: ORACLE data block corrupted (file # {num}, block # {block})\n"
                    f"ORA-01110: data file {num}: '{path}'",
                 "block_corruption", [1578, 1110], forced=f)

    def sc_background_death(self, t, f, proc: str):
        code = {"lgwr": 470, "dbw0": 471, "smon": 474}[proc]
        name = {"lgwr": "LGWR", "dbw0": "DBWR", "smon": "SMON"}[proc]
        pmon = self.pid("pmon")
        self.add(t, f"Errors in file {self.trace('pmon')}:\n"
                    f"ORA-{code:05d}: {name} process terminated with error\n"
                    f"PMON (ospid: {pmon}): terminating the instance due to ORA error {code}",
                 "instance_crash", [code], forced=f, lifecycle=True, jitter=False)
        self.add(t + timedelta(seconds=1),
                 f"System state dump requested by (instance=1, osid={pmon} (PMON)), "
                 f"summary=[abnormal instance termination].", lifecycle=True, jitter=False)
        self.add(t + timedelta(seconds=3), f"Instance terminated by PMON, pid = {pmon}", lifecycle=True, jitter=False)
        self.startup(t + timedelta(minutes=self.rng.uniform(4, 15)), crash=True,
                     down_from=t + timedelta(seconds=1))

    def sc_redo_corruption(self, t, f):
        group = self.group_at(t)
        when = t.astimezone(self.zone).strftime("%m/%d/%Y %H:%M:%S")
        self.add(t, f"Errors in file {self.trace('arc0')}:\n"
                    f"ORA-00353: log corruption near block {self.rng.randint(1000, 90000)} change {self.scn_at(t)} time {when}\n"
                    f"ORA-00312: online log {group} thread 1: '{self.redo(group)}'",
                 "redo_corruption", [353, 312], forced=f)

    def sc_redo_member_missing(self, t, f):
        group = self.rng.randint(1, 4)
        self.add(t, f"Errors in file {self.trace('lgwr')}:\n"
                    f"ORA-00312: online log {group} thread 1: '{self.redo(group, 'b')}'\n"
                    "ORA-27037: unable to obtain file status\n"
                    "Linux-x86_64 Error: 2: No such file or directory\nAdditional information: 7",
                 "redo_member_missing", [312, 27037], forced=f)

    def sc_io_error(self, t, f):
        num, path = self.datafile()
        self.add(t, f"Errors in file {self.trace('dbw0')}:\n"
                    "ORA-27072: File I/O error\nLinux-x86_64 Error: 5: Input/output error\n"
                    f"Additional information: 4\nAdditional information: {self.rng.randint(1000, 900000)}\n"
                    f"ORA-01110: data file {num}: '{path}'",
                 "io_error", [27072, 1110], forced=f)

    def sc_datafile_missing(self, t, f):
        num, path = self.datafile()
        self.add(t, f"Errors in file {self.trace('dbw0')}:\n"
                    f"ORA-01157: cannot identify/lock data file {num} - see DBWR trace file\n"
                    f"ORA-01110: data file {num}: '{path}'\n"
                    "ORA-27037: unable to obtain file status\n"
                    "Linux-x86_64 Error: 2: No such file or directory\nAdditional information: 7",
                 "datafile_missing", [1157, 1110, 27037], forced=f)

    def sc_media_recovery(self, t, f):
        num, path = self.datafile()
        self.add(t, f"Errors in file {self.trace('ora')}:\n"
                    f"ORA-01113: file {num} needs media recovery\n"
                    f"ORA-01110: data file {num}: '{path}'",
                 "media_recovery_needed", [1113, 1110], forced=f)

    def sc_max_processes(self, t, f):
        m = 0.0
        for _ in range(self.rng.randint(2, 8)):
            self.add(t + timedelta(minutes=m),
                     "ORA-00020: maximum number of processes (1500) exceeded\n"
                     " ORA-20 errors will not be written to the alert log for\n"
                     " the next minute. Please look at trace files to see all\n"
                     " the ORA-20 errors.",
                     "logon_storm", [20], forced=f)
            m += self.rng.uniform(1.0, 4.0)

    def sc_max_sessions(self, t, f):
        self.add(t, f"Errors in file {self.trace('ora')}:\nORA-00018: maximum number of sessions exceeded",
                 "logon_storm", [18], forced=f)

    def sc_standby_network(self, t, f, code: int):
        msg = {12537: "TNS:connection closed",
               12170: "TNS:Connect timeout occurred",
               3113: "end-of-file on communication channel",
               12514: "TNS:listener does not currently know of service requested in connect descriptor"}[code]
        tt = self.pid("tt00")
        self.add(t, f"TT00 (PID:{tt}): Error {code} received logging on to the standby\n"
                    f"Errors in file {self.trace('tt00')}:\nORA-{code:05d}: {msg}",
                 "standby_network", [code], forced=f)
        self.add(t + timedelta(seconds=self.rng.randint(30, 300)),
                 f"TT00 (PID:{tt}): Attempting LAD:2 network reconnect ({code})\n"
                 f"TT00 (PID:{tt}): LAD:2 network reconnect successful", "standby_network")

    def sc_deadlock(self, t, f):
        tr = self.trace("ora")
        self.add(t, f"Errors in file {tr}:\n"
                    "ORA-00060: Deadlock detected. See Note 60.1 at My Oracle Support for Troubleshooting "
                    f"ORA-60 Errors. More info in file {tr}.",
                 "deadlock", [60], forced=f)

    def sc_job_failure(self, t, f):
        job = self.rng.choice(["j000", "j001", "j002", "j003"])
        self.add(t, f"Errors in file {self.trace(job)}:\n"
                    f"ORA-12012: error on auto execute of job \"SYS\".\"ORA$AT_OS_OPT_SY_{self.rng.randint(1000, 9999)}\"\n"
                    "ORA-01013: user requested cancel of current operation\n"
                    f"ORA-06512: at \"SYS.DBMS_STATS\", line {self.rng.randint(40000, 55000)}\n"
                    f"ORA-06512: at \"SYS.DBMS_STATS_INTERNAL\", line {self.rng.randint(20000, 26000)}\n"
                    "ORA-06512: at line 1",
                 "job_failure", [12012, 1013, 6512], forced=f)

    # name -> (function, daily rate, time-of-day profile)
    def scenarios(self):
        s = self
        return {
            "internal_600":        (s.sc_internal_600, 0.10, "any"),
            "internal_7445":       (s.sc_internal_7445, 0.04, "any"),
            "recovery_area_full":  (s.sc_fra_full, 0.04, "night"),
            "tablespace_table":    (lambda t, f: s.sc_space(t, f, "table"), 0.15, "business"),
            "tablespace_index":    (lambda t, f: s.sc_space(t, f, "index"), 0.06, "business"),
            "tablespace_partition": (lambda t, f: s.sc_space(t, f, "partition"), 0.05, "night"),
            "tablespace_lob":      (lambda t, f: s.sc_space(t, f, "lob"), 0.03, "business"),
            "temp_full":           (s.sc_temp_full, 0.30, "night"),
            "undo_full":           (s.sc_undo_extend, 0.10, "night"),
            "snapshot_too_old":    (s.sc_snapshot_too_old, 0.50, "night"),
            "shared_pool":         (s.sc_shared_pool, 0.05, "business"),
            "process_memory":      (s.sc_pga, 0.05, "any"),
            "block_corruption":    (s.sc_corruption, 0.02, "any"),
            "crash_lgwr":          (lambda t, f: s.sc_background_death(t, f, "lgwr"), 0.005, "any"),
            "crash_dbwr":          (lambda t, f: s.sc_background_death(t, f, "dbw0"), 0.005, "any"),
            "crash_smon":          (lambda t, f: s.sc_background_death(t, f, "smon"), 0.005, "any"),
            "redo_corruption":     (s.sc_redo_corruption, 0.005, "any"),
            "redo_member_missing": (s.sc_redo_member_missing, 0.02, "any"),
            "io_error":            (s.sc_io_error, 0.02, "any"),
            "datafile_missing":    (s.sc_datafile_missing, 0.01, "any"),
            "media_recovery":      (s.sc_media_recovery, 0.01, "any"),
            "max_processes":       (s.sc_max_processes, 0.04, "business"),
            "max_sessions":        (s.sc_max_sessions, 0.02, "business"),
            "standby_12537":       (lambda t, f: s.sc_standby_network(t, f, 12537), 0.30, "any"),
            "standby_12170":       (lambda t, f: s.sc_standby_network(t, f, 12170), 0.20, "any"),
            "standby_3113":        (lambda t, f: s.sc_standby_network(t, f, 3113), 0.20, "any"),
            "standby_12514":       (lambda t, f: s.sc_standby_network(t, f, 12514), 0.10, "any"),
            "deadlock":            (s.sc_deadlock, 0.50, "business"),
            "job_failure":         (s.sc_job_failure, 0.20, "night"),
        }

    def incidents_day(self, day: date, forced: set[str]):
        for name, (fn, rate, profile) in self.scenarios().items():
            count = self.poisson(rate * self.error_rate)
            for _ in range(count):
                fn(self.random_time(day, profile), False)
            if name in forced:
                fn(self.random_time(day, profile), True)

    def is_down(self, when: datetime) -> bool:
        return any(a <= when <= b for a, b in self.downtime)

    def suppressed(self, e: Entry) -> bool:
        """Nothing is logged while the instance is down, and no logs get archived while the archiver is stuck."""
        if e.lifecycle or e.forced:
            return False
        if self.is_down(e.when):
            return True
        return "Archived Log entry" in e.text and any(a <= e.when <= b for a, b in self.archiver_stopped)


# ---------------------------------------------------------------------------
# Writing
# ---------------------------------------------------------------------------

def check_codes(entry: Entry):
    """Guard against template mistakes: declared codes must match the text."""
    found = {norm(c) for c in ORA_RE.findall(entry.text)}
    if found != set(entry.codes):
        raise AssertionError(f"Declared codes {entry.codes} do not match text codes {sorted(found)}:\n{entry.text}")


def generate(args) -> int:
    rng = random.Random(args.seed)
    sim = AlertLogSimulator(args.db_name, args.tz, args.format, rng, args.error_rate)
    out = args.out or Path(f"generated/alert_{sim.db}.log")
    expected = args.expected or out.with_name("expected_incidents.csv")
    out.parent.mkdir(parents=True, exist_ok=True)

    start_day = date.fromisoformat(args.start)
    # In size mode there is no day limit: keep simulating until the target size is reached
    max_days = args.days if args.size_mb is None else 10**6
    target = None if args.size_mb is None else int(args.size_mb * 1024 * 1024)

    # Guarantee every scenario appears at least once within the first week
    names = list(sim.scenarios())
    span = max(1, min(max_days, 7))
    forced_by_day: dict[int, set] = {}
    if not args.no_ensure_all:
        for name in names:
            forced_by_day.setdefault(rng.randrange(span), set()).add(name)

    # The log begins with an instance startup
    sim.startup(sim.at_local(start_day, 0.0) - timedelta(minutes=5), crash=False)

    written = 0
    incidents = []
    pending: list[Entry] = []
    with open(out, "w", encoding="utf-8") as log, open(expected, "w", newline="", encoding="utf-8") as exp:
        writer = csv.writer(exp)
        writer.writerow(["Timestamp", "Scenario", "Primary Code", "Related Codes"])
        stop = False
        for d in range(max_days):
            day = start_day + timedelta(days=d)
            sim.routine_day(day)
            sim.incidents_day(day, forced_by_day.get(d, set()))
            pending.extend(sim.entries)
            sim.entries = []
            pending.sort(key=lambda e: (e.when, e.order))
            cutoff = sim.local_midnight_utc(day + timedelta(days=1)) if d < max_days - 1 else None
            keep = []
            for e in pending:
                if cutoff is not None and e.when >= cutoff:
                    keep.append(e)
                    continue
                if sim.suppressed(e):
                    continue
                if e.codes:
                    check_codes(e)
                ts = sim.ts_text(e.when)
                block = f"{ts}\n{e.text}\n"
                log.write(block)
                written += len(block.encode("utf-8"))
                if e.codes:
                    writer.writerow([ts, e.scenario, e.codes[0], " ".join(dict.fromkeys(e.codes[1:]))])
                    incidents.append(e)
                if target and written >= target:
                    stop = True
                    break
            pending = keep
            if stop:
                break

    print_summary(out, expected, written, incidents, sim)
    return 0


def print_summary(out: Path, expected: Path, size: int, incidents: list[Entry], sim):
    primary = Counter(e.codes[0] for e in incidents)
    every = Counter(c for e in incidents for c in dict.fromkeys(e.codes))
    if incidents:
        first, last = sim.ts_text(incidents[0].when), sim.ts_text(incidents[-1].when)
    else:
        first = last = "-"
    print(f"Alert log:          {out}  ({size / 1024 / 1024:.2f} MB)")
    print(f"Expected incidents: {expected}")
    print(f"Incidents written:  {len(incidents)}  ({first}  to  {last})\n")
    print(f"{'CODE':<11}{'AS INCIDENT':>12}{'ANYWHERE':>10}")
    for code in sorted(every):
        print(f"{code:<11}{primary.get(code, 0):>12}{every[code]:>10}")


def build_arg_parser():
    p = argparse.ArgumentParser(description="Generate a realistic Oracle alert log for testing.")
    p.add_argument("--out", type=Path, help="Alert log path (default generated/alert_<DB>.log)")
    p.add_argument("--expected", type=Path, help="Ground-truth CSV path (default next to the log)")
    p.add_argument("--days", type=int, default=30, help="Days of activity to simulate (default 30)")
    p.add_argument("--size-mb", type=float, help="Keep generating until the log reaches this size")
    p.add_argument("--start", default="2026-10-01", help="First day, YYYY-MM-DD (default 2026-10-01)")
    p.add_argument("--tz", default="America/Toronto", help="Time zone for timestamps (default America/Toronto)")
    p.add_argument("--db-name", default="PRODDB", help="Database name (default PRODDB)")
    p.add_argument("--format", choices=["iso", "legacy"], default="iso",
                   help="iso = 12c+ timestamps, legacy = 11g style (default iso)")
    p.add_argument("--error-rate", type=float, default=1.0, help="Multiply incident frequency (default 1.0)")
    p.add_argument("--seed", type=int, default=42, help="Random seed for repeatable output (default 42)")
    p.add_argument("--no-ensure-all", action="store_true",
                   help="Don't force every incident type to appear at least once")
    return p


if __name__ == "__main__":
    sys.exit(generate(build_arg_parser().parse_args()))
