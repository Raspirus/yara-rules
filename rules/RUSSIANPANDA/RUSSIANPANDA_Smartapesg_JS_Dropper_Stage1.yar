
rule RUSSIANPANDA_Smartapesg_JS_Dropper_Stage1 : FILE
{
	meta:
		description = "Detects SmartApeSG initial JavaScript file"
		author = "RussianPanda"
		id = "9513f323-c315-5ae2-92a5-c831d0a7ce2a"
		date = "2024-01-11"
		modified = "2024-01-11"
		reference = "https://medium.com/walmartglobaltech/smartapesg-4605157a5b80"
		source_url = "https://github.com/RussianPanda95/Yara-Rules/blob/c65f3c62711bf141e4eb926ffe3a9880e5331974/SmartApeSG/SmartApeSG_JS_dropper_stage1.yar#L1-L18"
		license_url = "N/A"
		hash = "8769d9ebcf14b24a657532cd96f9520f54aa0e799399d840285311dfebe3fb15"
		logic_hash = "de7e4ec30c780699b46de7baf2a916fdb7331da2ee7c2d637422ea664cd03b82"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$a1 = "'GE'+'T'"
		$a2 = "'GE','T'"
		$s1 = "pt.Creat"
		$s2 = "L2.ServerX"
		$s3 = "ponseText"
		$s4 = "MLHTTP.6.0"
		$s5 = /\/news\.php\?([0-9]|[1-9][0-9]|100)/

	condition:
		all of ($s*) and filesize <1MB and any of ($a*)
}