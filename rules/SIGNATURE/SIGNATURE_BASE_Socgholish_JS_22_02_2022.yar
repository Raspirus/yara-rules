
rule SIGNATURE_BASE_Socgholish_JS_22_02_2022 : FILE
{
	meta:
		description = "Detects SocGholish fake update Javascript files 22.02.2022"
		author = "Wojciech Cieślak"
		id = "68d2dbb7-0079-527a-92c7-450c3dd953b3"
		date = "2022-02-22"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/yara/crime_socgholish.yar#L53-L72"
		license_url = "https://github.com/Neo23x0/signature-base/blob/6b8e2a00e5aafcfcfc767f3f53ae986cf81f968a/LICENSE"
		hash = "3e14d04da9cc38f371961f6115f37c30"
		hash = "dffa20158dcc110366f939bd137515c3"
		hash = "afee3af324951b1840c789540d5c8bff"
		hash = "c04a1625efec27fb6bbef9c66ca8372b"
		hash = "d08a2350df5abbd8fd530cff8339373e"
		logic_hash = "fd529cbb511ff6bcf37b44b835e021b28763922f7726ff67db5cbb3f9193c7ae"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$s1 = "encodeURIComponent(''+" ascii
		$s2 = "['open']('POST'," ascii
		$s3 = "new ActiveXObject('MSXML2.XMLHTTP');" ascii

	condition:
		filesize <5KB and all of them
}