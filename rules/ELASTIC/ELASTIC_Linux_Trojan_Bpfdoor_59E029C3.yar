
rule ELASTIC_Linux_Trojan_Bpfdoor_59E029C3 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Bpfdoor (Linux.Trojan.BPFDoor)"
		author = "Elastic Security"
		id = "59e029c3-a57c-44ad-a554-432efc6b591a"
		date = "2022-05-10"
		modified = "2022-05-10"
		reference = "https://www.elastic.co/security-labs/a-peek-behind-the-bpfdoor"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_BPFDoor.yar#L1-L24"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "144526d30ae747982079d5d340d1ff116a7963aba2e3ed589e7ebc297ba0c1b3"
		logic_hash = "64620a3404b331855d0b8018c1626c88cb28380785beac1a391613ae8dc1b1bf"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "cc9b75b1f1230e3e2ed289ef5b8fa2deec51197e270ec5d64ff73722c43bb4e8"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a1 = "hald-addon-acpi: listening on acpi kernel interface /proc/acpi/event" ascii fullword
		$a2 = "/sbin/iptables -t nat -D PREROUTING -p tcp -s %s --dport %d -j REDIRECT --to-ports %d" ascii fullword
		$a3 = "avahi-daemon: chroot helper" ascii fullword
		$a4 = "/sbin/mingetty /dev/tty6" ascii fullword
		$a5 = "ttcompat" ascii fullword

	condition:
		all of them
}