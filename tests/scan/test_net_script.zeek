# @TEST-EXEC: zeek -r $TRACES/net_script_scan.pcap ../../../scripts %INPUT
# @TEST-EXEC: zeek-cut src p note msg sub < notice.log > notice.tmp && mv notice.tmp notice.log || touch notice.log
# @TEST-EXEC: btest-diff notice.log
redef Notice::ignored_types += {Site::New_Used_Address_Space};
redef Site::local_nets = {
    10.0.0.0/8,
};
