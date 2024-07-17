rule ELASTIC_Linux_Trojan_Bpfdoor_0F768F60 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Bpfdoor (Linux.Trojan.BPFDoor)"
		author = "Elastic Security"
		id = "0f768f60-1d6c-4af9-8ae3-c1c8fbbd32f4"
		date = "2022-05-10"
		modified = "2022-05-10"
		reference = "https://www.elastic.co/security-labs/a-peek-behind-the-bpfdoor"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_BPFDoor.yar#L26-L50"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "3a1b174f0c19c28f71e1babde01982c56d38d3672ea14d47c35ae3062e49b155"
		logic_hash = "1aaa74c2d8fbb230cbfc0e08fd6865b5f7e90e4abcdb97121e52afb7569b2dbc"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "55097020a70d792e480542da40b91fd9ab0cc23f8736427f398998962e22348e"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a1 = "hald-addon-acpi: listening on acpi kernel interface /proc/acpi/event" ascii fullword
		$a2 = "/sbin/mingetty /dev/tty7" ascii fullword
		$a3 = "pickup -l -t fifo -u" ascii fullword
		$a4 = "kdmtmpflush" ascii fullword
		$a5 = "avahi-daemon: chroot helper" ascii fullword
		$a6 = "/sbin/auditd -n" ascii fullword

	condition:
		all of them
}