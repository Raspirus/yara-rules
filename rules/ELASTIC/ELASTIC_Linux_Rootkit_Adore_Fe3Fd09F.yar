rule ELASTIC_Linux_Rootkit_Adore_Fe3Fd09F : FILE MEMORY
{
	meta:
		description = "Detects Linux Rootkit Adore (Linux.Rootkit.Adore)"
		author = "Elastic Security"
		id = "fe3fd09f-d170-4bb0-bc8d-6d61bdc22164"
		date = "2021-04-06"
		modified = "2021-09-16"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Rootkit_Adore.yar#L1-L19"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "f4e532b840e279daf3d206e9214a1b065f97deb7c1487a34ac5cbd7cbbf33e1a"
		logic_hash = "cc07efb9484562cd870649a38126f08aa4e99ed5ad4662ece0488d9ffd97520e"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "2bab2a4391359c6a7148417b010887d0754b91ac99820258e849e81f7752069f"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$a = { 89 C0 89 45 F4 83 7D F4 00 75 17 68 E4 A1 04 08 }

	condition:
		all of them
}