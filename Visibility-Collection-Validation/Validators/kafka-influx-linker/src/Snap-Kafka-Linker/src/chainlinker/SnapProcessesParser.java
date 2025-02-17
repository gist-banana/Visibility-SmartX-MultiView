package chainlinker;

public class SnapProcessesParser extends SnapPluginParser {
	public SnapProcessesParser() {
		super();
		// All these data forms must be updated when snap publisher's output format is changed.
		
		typeMap.put("/intel/procfs/processes/running", lClass);
		typeMap.put("/intel/procfs/processes/sleeping", lClass);
		typeMap.put("/intel/procfs/processes/waiting", lClass);
		typeMap.put("/intel/procfs/processes/zombie", lClass);
		typeMap.put("/intel/procfs/processes/stopped", lClass);
		typeMap.put("/intel/procfs/processes/tracing", lClass);
		typeMap.put("/intel/procfs/processes/dead", lClass);
		typeMap.put("/intel/procfs/processes/wakekill", lClass);
		typeMap.put("/intel/procfs/processes/waking", lClass);
		typeMap.put("/intel/procfs/processes/parked", lClass);
		
		// Needs more information on process name
		// Pattern: /intel/procfs/processes/(alphanumerical or _ or - or : or .)/(ps_vm or ps_rss or ps_data or ps_code or ps_stacksize or ps_cputime_user or ps_cputime_system or ps_pagefaults_min or ps_pagefaults_maj or ps_disk_ops_syscr or ps_disk_ops_syscw or ps_disk_octets_rchar or ps_disk_octets_wchar or ps_count)
		 regexTypeMap.put("^\\/intel\\/procfs\\/processes\\/([0-9]|[a-z]|[A-Z]|_|\\-|:|\\.)*\\/(ps_vm|ps_rss|ps_data|ps_code|ps_stacksize|ps_cputime_user|ps_cputime_system|ps_pagefaults_min|ps_pagefaults_maj|ps_disk_ops_syscr|ps_disk_ops_syscw|ps_disk_octets_rchar|ps_disk_octets_wchar|ps_count)$", lClass);
		
		regexSet = regexTypeMap.keySet();
	}
}
