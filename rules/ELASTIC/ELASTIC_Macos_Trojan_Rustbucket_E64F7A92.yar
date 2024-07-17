
rule ELASTIC_Macos_Trojan_Rustbucket_E64F7A92 : FILE MEMORY
{
	meta:
		description = "Detects Macos Trojan Rustbucket (MacOS.Trojan.RustBucket)"
		author = "Elastic Security"
		id = "e64f7a92-e530-4d0b-8ecb-fe5756ad648c"
		date = "2023-06-26"
		modified = "2023-06-29"
		reference = "https://www.elastic.co/security-labs/DPRK-strikes-using-a-new-variant-of-rustbucket"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/MacOS_Trojan_RustBucket.yar#L1-L22"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "9ca914b1cfa8c0ba021b9e00bda71f36cad132f27cf16bda6d937badee66c747"
		logic_hash = "bd6005d72faba6aaeebdcbd8c771995cbfc667faf01eb93825afe985954a47fc"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "f9907f46c345a874b683809f155691723e3a6df7c48f6f4e6eb627fb3dd7904d"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"

	strings:
		$user_agent = "User-AgentMozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0)"
		$install_log = "/var/log/install.log"
		$timestamp = "%Y-%m-%d %H:%M:%S"

	condition:
		all of them
}