##! Vulnerability Scan detection.

# ..Authors: Foster McLane
#            Justin Azoff
#            All the authors of the old scan.bro

@load base/protocols/conn
@load base/frameworks/notice

@load base/utils/time

module Vuln;

export {
   redef enum Notice::Type += {
      ## Vuln scans detect that an attacking host appears to be
      ## scanning a single victim host on several ports and
      ## sending/receiving some data.  This notice is generated
      ## when an attacking host attempts to connect to
      ## :zeek:id:`Vuln::scan_threshold`
      ## unique ports on a single host over the previous
      ## :zeek:id:`Vuln::scan_interval`
      ## time range with data transfer over
      ## :zeek:id:`Vuln::vuln_threshold`.
      Scan::Vuln_Scan,
   };

   ## An individual scan destination
   type Attempt: record {
      victim: addr;
      scanned_port: port;
   };

   ## Information tracked for each scanner
   type Scan_Info: record {
      first_seen: time;
      attempts: set[Attempt];
      port_counts: table[port] of count;
      data_rx: count;
      data_tx: count;
   };

   ## Failed connection attempts are tracked until not seen for this interval.
   ## A higher interval will detect slower scanners, but may also yield more
   ## false positives.
   const scan_timeout = 5min &redef;

   ## The threshold of the unique number of host+ports a remote scanning host
   ## has to have failed connections with
   const scan_threshold = 25 &redef;

   ## The threshold of data transfer to consider the scanner talking
   const vuln_threshold = 1024 &redef;

   ## The threshold of the unique number of host+ports a local scanning host
   ## has to have failed connections with
   const local_scan_threshold = 250 &redef;

   ## Override this hook to ignore particular scan connections
   global Scan::scan_policy: hook(scanner: addr, victim: addr, scanned_port: port);

   global scan_attempt: event(scanner: addr, attempt: Attempt, attack_rx: count, attack_tx: count);
   global attacks: table[addr] of Scan_Info &read_expire=scan_timeout &redef;
   global recent_scan_attempts: table[addr] of set[Attempt] &create_expire=1mins;

   global adjust_known_scanner_expiration: function(s: table[addr] of interval, idx: addr): interval;
   global known_scanners: table[addr] of interval &create_expire=10secs &expire_func=adjust_known_scanner_expiration;
}

# There's no way to set a key to expire at a specific time, so we
# First set the keys value to the duration we want, and then
# use expire_func to adjust it to the desired time.
event Notice::begin_suppression(ts: time, suppress_for: interval, note: Notice::Type, identifier: string) {
   if (note == Scan::Vuln_Scan) {
      local src = to_addr(identifier);
      known_scanners[src] = suppress_for;
      delete recent_scan_attempts[src];
   }
}

function adjust_known_scanner_expiration(s: table[addr] of interval, idx: addr): interval {
   local duration = s[idx];
   s[idx] = 0secs;
   return duration;
}

function analyze_unique_hostports(attempts: set[Attempt]): Notice::Info {
   local ports: set[port];
   local victims: set[addr];

   local ports_str: set[string];
   local victims_str: set[string];

   for (a in attempts) {
      add victims[a$victim];
      add ports[a$scanned_port];

      add victims_str[cat(a$victim)];
      add ports_str[cat(a$scanned_port)];
   }

   if (|ports| == 1) {
      for (p in ports) {
         return [$note=Scan::Vuln_Scan, $msg=fmt("%s unique hosts on port %s", |victims|, p), $p=p];
      }
   }
   if(|victims| == 1) {
      for (v in victims)
         return [$note=Scan::Vuln_Scan, $msg=fmt("%s unique ports on host %s", |ports|, v)];
   }
   if(|ports| <= 5) {
      local ports_string = join_string_set(ports_str, ", ");
      return [$note=Scan::Vuln_Scan, $msg=fmt("%s unique hosts on ports %s", |victims|, ports_string)];
   }
   if(|victims| <= 5) {
      local victims_string = join_string_set(victims_str, ", ");
      return [$note=Scan::Vuln_Scan, $msg=fmt("%s unique ports on hosts %s", |ports|, victims_string)];
   }

   return [$note=Scan::Vuln_Scan, $msg=fmt("%d hosts on %d ports", |victims|, |ports|)];
}

function generate_notice(scanner: addr, si: Scan_Info): Notice::Info {
   local side = Site::is_local_addr(scanner) ? "local" : "remote";
   local dur = duration_to_mins_secs(network_time() - si$first_seen);
   local n = analyze_unique_hostports(si$attempts);
   n$msg = fmt("%s performed a vulnerability scan on at least %s in %s", scanner, n$msg, dur);
   n$src = scanner;
   n$sub = side;
   n$identifier = cat(scanner);
   return n;
}

function add_scan_attempt(scanner: addr, attempt: Attempt, attack_rx: count, attack_tx: count) {
   if (scanner in known_scanners)
      return;

   local si: Scan_Info;
   local attempts: set[Attempt];
   local port_counts: table[port] of count;

   if (scanner !in attacks) {
      attempts = set();
      port_counts = table();
      si = Scan_Info($first_seen=network_time(), $attempts=attempts, $port_counts=port_counts, $data_rx=0, $data_tx=0);
      attacks[scanner] = si;
   }
   else {
      si = attacks[scanner];
      attempts = si$attempts;
      port_counts = si$port_counts;
   }

   if (attempt !in attempts) {
      add attempts[attempt];
      if (attempt$scanned_port !in port_counts)
         port_counts[attempt$scanned_port] = 1;
      else
         ++port_counts[attempt$scanned_port];
   }

   si$data_rx += attack_rx;
   si$data_tx += attack_tx;

   local is_vuln = si$data_rx + si$data_tx > vuln_threshold;

   local thresh: count;
   local is_local = Site::is_local_addr(scanner);

   thresh = is_local ? local_scan_threshold : scan_threshold;

   local is_scan = |attempts| >= thresh;

   if (is_scan) {
      if (is_vuln) {
         local note = generate_notice(scanner, si);
         NOTICE(note);
         delete attacks[scanner];
         known_scanners[scanner] = 1hrs;
      }
   }
}

@if (Cluster::is_enabled())
   @ifdef (Cluster::worker2manager_events)
      redef Cluster::worker2manager_events += /Vuln::scan_attempt/;
   @endif

   function add_scan(id: conn_id, attack_rx: count, attack_tx: count) {
      local scanner      = id$orig_h;
      local victim       = id$resp_h;
      local scanned_port = id$resp_p;

      if (scanner in known_scanners)
         return;

      if (hook Scan::scan_policy(scanner, victim, scanned_port)) {
         local attempt = Attempt($victim=victim, $scanned_port=scanned_port);
         if (scanner !in recent_scan_attempts)
            recent_scan_attempts[scanner] = set();
         if (attempt in recent_scan_attempts[scanner])
            return;
         add recent_scan_attempts[scanner][attempt];
         @ifdef (Cluster::worker2manager_events)
            event Vuln::scan_attempt(scanner, attempt, attack_rx, attack_tx);
         @else
            Cluster::publish_hrw(Vuln::scan_attempt, scanner, attempt);
         @endif

         local thresh = Site::is_local_addr(scanner) ? local_scan_threshold : scan_threshold;
         if (|recent_scan_attempts[scanner]| >= thresh) {
            known_scanners[scanner] = 1hrs;
            delete recent_scan_attempts[scanner];
         }
      }
   }

@if ( Cluster::local_node_type() != Cluster::WORKER )
   event Vuln::scan_attempt(scanner: addr, attempt: Attempt, attack_rx: count, attack_tx: count) {
      add_scan_attempt(scanner, attempt, attack_rx, attack_tx);
   }
@endif
@else
function add_scan(id: conn_id, attack_rx: count, attack_tx: count) {
   local scanner      = id$orig_h;
   local victim       = id$resp_h;
   local scanned_port = id$resp_p;

   if (hook Scan::scan_policy(scanner, victim, scanned_port)) {
      add_scan_attempt(scanner, Attempt($victim=victim, $scanned_port=scanned_port), attack_rx, attack_tx);
   }
}
@endif

event connection_attempt(c: connection) {
   if (c$history == "S" || c$history == "SW")
      add_scan(c$id, 0, 0);
}

event connection_rejected(c: connection) {
   if (c$history == "Sr" || c$history == "SWr")
      add_scan(c$id, 0, 0);
}

event connection_state_remove(c: connection) {
   if (c$conn?$orig_bytes && c$conn?$resp_bytes && c$conn$proto != icmp)
      add_scan(c$id, c$conn$orig_bytes, c$conn$resp_bytes);
}
