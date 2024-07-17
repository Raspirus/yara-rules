
rule VOLEXITY_Apt_Win_Avburner : SNAKECHARMER
{
	meta:
		description = "Detects AVBurner based on a combination of API calls used, hard-coded strings and bytecode patterns."
		author = "threatintel@volexity.com"
		id = "1bde0861-4820-5bb1-98a3-516092c91be0"
		date = "2023-01-02"
		modified = "2023-03-07"
		reference = "https://www.trendmicro.com/en_us/research/22/k/hack-the-real-box-apt41-new-subgroup-earth-longzhi.html"
		source_url = "https://github.com/volexity/threat-intel/blob/cb213e6d64022494a2ae7a9e65dfbf254a99b144/2023/2023-03-07 AVBurner/yara.yar#L1-L36"
		license_url = "https://github.com/volexity/threat-intel/blob/cb213e6d64022494a2ae7a9e65dfbf254a99b144/LICENSE.txt"
		hash = "4b1b1a1293ccd2c0fd51075de9376ebb55ab64972da785153fcb0a4eb523a5eb"
		logic_hash = "56ff6c8a4b737959a1219699a0457de1f0c34fead4299033840fb23c56a0caad"
		score = 75
		quality = 80
		tags = "SNAKECHARMER"
		memory_suitable = 1
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

	strings:
		$api1 = "PspCreateProcessNotifyRoutineAddress" wide
		$api2 = "PspCreateThreadNotifyRoutineAddress" wide
		$api3 = "PspLoadImageNotifyRoutineAddress" wide
		$str1 = "\\\\.\\RTCORE64" wide
		$str2 = "\\\\%ws/pipe/%ws" wide
		$str3 = "CreateServerW Failed %u" wide
		$str4 = "OpenSCManager Failed %u" wide
		$str5 = "Get patternAddress" wide
		$pattern1 = { 4C 8B F9 48 8D 0C C1 E8 }
		$pattern2 = { 48 8D 0C DD 00 00 00 00  45 33 C0 49 03 CD 48 8B }
		$pattern3 = { 48 8D 04 C1 48 89 45 70 48 8B C8 E8 }
		$pattern4 = { 49 8D 0C FC 45 33 C0 48 8B D6 E8 00 00 00 00 00}
		$pattern5 = { 45 33 C0 48 8D 0C D9 48 8B D7 E8 00 00 00 00 00 00 00 00 00 00 00 00 00 }
		$pattern6 = { 41 0F BA 6D 00 0A BB 01 00 00 00 4C 8B F2 4C 8B F9 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

	condition:
		all of ($api*) or all of ($str*) or all of ($pattern*)
}