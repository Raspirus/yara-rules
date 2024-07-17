
rule ELASTIC_Linux_Trojan_Dinodasrat_1D371D10 : FILE MEMORY
{
	meta:
		description = "Detects Linux Trojan Dinodasrat (Linux.Trojan.DinodasRAT)"
		author = "Elastic Security"
		id = "1d371d10-b2ae-4ea0-ad37-f5a5a571a6fc"
		date = "2024-04-02"
		modified = "2024-06-12"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Trojan_DinodasRAT.yar#L1-L24"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "bf830191215e0c8db207ea320d8e795990cf6b3e6698932e6e0c9c0588fc9eff"
		logic_hash = "933e78882be1d8dd9553ba90f038963d1b6f8f643888258541b7668aa3434808"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "a53bf582ad95320dd6f432cb7290ce604aa558e4ecf6ae4e11d7985183969db1"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$s1 = "int MyShell::createsh()"
		$s2 = "/src/myshell.cpp"
		$s3 = "/src/inifile.cpp"
		$s4 = "Linux_%s_%s_%u_V"
		$s5 = "/home/soft/mm/rootkit/"
		$s6 = "IniFile::load_ini_file"

	condition:
		4 of them
}