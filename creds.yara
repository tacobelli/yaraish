rule find_credentials
{
meta: 
	Author = "Tony Iacobelli"=
	//Regex lifted from YAR: https://raw.githubusercontent.com/nielsing/yar/master/config/yarconfig.json  
strings:
	$RSA_Private_Key = /-----BEGIN RSA PRIVATE KEY-----/
condition:
	any of them
}
