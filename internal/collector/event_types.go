package collector

func mapEventType(log string, id int) string {
	switch log {
	case "Security":
		switch id {
		case 4688:
			return "process_create"
		case 4697, 7045:
			return "service_install"
		case 1102:
			return "security_log_cleared"
		}
	case "Microsoft-Windows-Sysmon/Operational":
		switch id {
		case 1:
			return "process_create"
		case 3:
			return "network_connect"
		case 7:
			return "image_load"
		case 11:
			return "file_create"
		case 13:
			return "registry_set"
		}
	}
	return "unknown"
}
