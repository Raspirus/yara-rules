rule ELASTIC_Linux_Hacktool_Fontonlake_68Ad8568 : FILE MEMORY
{
	meta:
		description = "Detects Linux Hacktool Fontonlake (Linux.Hacktool.Fontonlake)"
		author = "Elastic Security"
		id = "68ad8568-2b00-4680-a83f-1689eff6099c"
		date = "2021-10-12"
		modified = "2022-01-26"
		reference = "https://github.com/elastic/protections-artifacts/"
		source_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/yara/rules/Linux_Hacktool_Fontonlake.yar#L1-L30"
		license_url = "https://github.com/elastic/protections-artifacts//blob/7607ac6ed3bb869356a16d2f7488f6744c68b134/LICENSE.txt"
		hash = "717953f52318e7687fc95626561cc607d4875d77ff7e3cf5c7b21cf91f576fa4"
		logic_hash = "63dd5769305c715e27e3c62160f7b0f65b57204009ed46383b5b477c67cfac8e"
		score = 75
		quality = 75
		tags = "FILE, MEMORY"
		fingerprint = "81936e696a525cf02070fa7cfa27574cdad37e1b3d8f278950390a1945c21611"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"

	strings:
		$s1 = "run_in_bash"
		$s2 = "run_in_ss"
		$s3 = "real_bash_fork"
		$s4 = "fake_bash_add_history"
		$s5 = "hook_bash_add_history"
		$s6 = "real_bash_add_history"
		$s7 = "real_current_user.5417"
		$s8 = "real_bash_execve"
		$s9 = "inject_so_symbol.c"
		$s10 = "/root/rmgr_ko/subhook-0.5/subhook_x86.c"
		$s11 = "|1|%ld|%d|%d|%d|%d|%s|%s"
		$s12 = "/proc/.dot3"

	condition:
		4 of them
}