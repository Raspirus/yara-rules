
rule SECUINFRA_DROPPER_WSHRAT_Stage_1 : FILE
{
	meta:
		description = "Detects the first stage of WSHRAT as obfuscated JavaScript"
		author = "SECUINFRA Falcon Team"
		id = "3bd363dc-3183-595e-931b-668eb17495f5"
		date = "2022-11-02"
		modified = "2022-02-27"
		reference = "https://bazaar.abuse.ch/sample/ad24ae27346d930e75283b10d4b949a4986c18dbd5872a91f073334a08169a14/"
		source_url = "https://github.com/SIFalcon/Detection/blob/2d7c66d7d16c7541bf2a9a83a7a6d334364a26fd/Yara/Dropper/wshrat.yar#L1-L18"
		license_url = "N/A"
		hash = "793eff1b2039727e76fdd04300d44fc6"
		logic_hash = "1390929d06bd1259dbab425fd4e953119f632be460f57756a0c226e9f510d75a"
		score = 75
		quality = 70
		tags = "FILE"

	strings:
		$a1 = "'var {0} = WS{1}teObject(\"ado{2}am\");"
		$b1 = "String[\"prototype\"]"
		$b2 = "this.replace("
		$b3 = "Array.prototype"

	condition:
		filesize <1500KB and $a1 and #b3>3 and #b1>2 and $b2
}