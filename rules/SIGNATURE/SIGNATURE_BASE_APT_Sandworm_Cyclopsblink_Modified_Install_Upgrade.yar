rule SIGNATURE_BASE_APT_Sandworm_Cyclopsblink_Modified_Install_Upgrade : FILE
{
	meta:
		description = "Detects notable strings identified within the modified install_upgrade executable, embedded within Cyclops Blink"
		author = "NCSC"
		id = "4c4f7262-df74-5f6a-afc0-df1fcae4741c"
		date = "2022-02-23"
		modified = "2023-12-05"
		reference = "https://www.ncsc.gov.uk/news/joint-advisory-shows-new-sandworm-malware-cyclops-blink-replaces-vpnfilter"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/apt_sandworm_cyclops_blink.yar#L57-L88"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		logic_hash = "69b89dbaf3e2661f376ff1be7c19e96c82bf84fd572fea422c109f8afdd1e5aa"
		score = 75
		quality = 85
		tags = "FILE"
		hash1 = "3adf9a59743bc5d8399f67cab5eb2daf28b9b863"
		hash2 = "c59bc17659daca1b1ce65b6af077f86a648ad8a8"
		hash3 = "7d61c0dd0cd901221a9dff9df09bb90810754f10"
		hash4 = "438cd40caca70cafe5ca436b36ef7d3a6321e858"

	strings:
		$ = "/pending/%010lu_%06d_%03d_p1"
		$ = "/pending/sysa_code_dir/test_%d_%d_%d_%d_%d_%d"
		$ = "etaonrishdlcupfm"
		$ = "/pending/WGUpgrade-dl.new"
		$ = "/pending/bin/install_upgraded"
		$ = {38 80 4C 00}
		$ = {38 80 4C 05}
		$ = {38 80 4C 04}
		$ = {3C 00 48 4D 60 00 41 43 90 09 00 00}

	condition:
		( uint32(0)==0x464c457f) and (6 of them )
}