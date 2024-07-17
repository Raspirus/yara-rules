
rule ELASTIC_Linux_Trojan_Springtail_35D5B90B : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Springtail (Linux.Trojan.Springtail)"
		author = "Elastic Security"
		id = "35d5b90b-f81d-4a10-828b-8315f8e87ca7"
		date = "2024-05-18"
		modified = "2024-06-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_Springtail.yar#L1-L24"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "30584f13c0a9d0c86562c803de350432d5a0607a06b24481ad4d92cdf7288213"
		logic_hash = "7158e60aedfde884d9ee01457abfe6d9b6b1df9cdc1c415231d98429866eaa6c"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "ca2d3ea7b23c0fc21afb9cfd2d6561727780bda65d2db1a5780b627ac7b07e66"
		severity = 100
		arch_context = "x86, arm64"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$systemd1 = "Description=syslogd"
		$systemd2 = "ExecStart=/bin/sh -c \"/var/log/syslogd\""
		$cron1 = "cron.txt@reboot"
		$cron2 = "/bin/shcrontab"
		$cron3 = "type/var/log/syslogdcrontab cron.txt"
		$uri = "/mir/index.php"

	condition:
		all of them
}