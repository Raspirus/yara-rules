rule ELASTIC_Windows_Ransomware_Hive_3Ed67Fe6 : FILE MEMORY
{
	meta:
		description = "Detects Windows Ransomware Hive (Windows.Ransomware.Hive)"
		author = "Elastic Security"
		id = "3ed67fe6-6347-4aef-898d-4cb267bcbfc7"
		date = "2021-08-26"
		modified = "2022-01-13"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Windows_Ransomware_Hive.yar#L23-L45"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "50ad0e6e9dc72d10579c20bb436f09eeaa7bfdbcb5747a2590af667823e85609"
		logic_hash = "a599f0d528bdbec00afa7e9a5cddec5e799ee755a7f30af70dde7d2459b70155"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "a15acde0841f08fc44fdc1fea01c140e9e8af6275a65bec4a7b762494c9e6185"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"

	strings:
		$a1 = "bmr|sql|oracle|postgres|redis|vss|backup|sstp"
		$a2 = "key.hive"
		$a3 = "Killing processes"
		$a4 = "Stopping services"
		$a5 = "Removing itself"

	condition:
		all of them
}