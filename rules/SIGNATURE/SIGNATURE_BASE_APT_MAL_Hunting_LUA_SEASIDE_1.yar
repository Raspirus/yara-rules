rule SIGNATURE_BASE_APT_MAL_Hunting_LUA_SEASIDE_1 : FILE
{
	meta:
		description = "Hunting rule looking for strings observed in SEASIDE samples."
		author = "Mandiant"
		id = "86eaff7b-4ca0-53cd-8886-da66a36c778f"
		date = "2023-06-15"
		modified = "2023-12-05"
		reference = "https://www.mandiant.com/resources/blog/barracuda-esg-exploited-globally"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_barracuda_esg_unc4841_jun23.yar#L136-L152"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		hash = "cd2813f0260d63ad5adf0446253c2172"
		logic_hash = "82b61325a78bf8ab09d426cfadceb614a256dfcafb2e1f75595de63593ed2574"
		score = 70
		quality = 85
		tags = "FILE"

	strings:
		$s1 = "function on_helo()"
		$s2 = "local bindex,eindex = string.find(helo,'.onion')"
		$s3 = "helosend = 'pd'..' '..helosend"
		$s4 = "os.execute(helosend)"

	condition:
		filesize <1MB and all of ($s*)
}