<?php 

class EmailVV{
	public $email,$port,$domain,$ip;
	public $verifier_email = "fatihmertdogancan@hotmail.com";			// write your email address
	private $mx;
    private $connect;
    private $debug_raw;

    private $_yahoo_signup_page_url = 'https://login.yahoo.com/account/create?specId=yidReg&lang=en-US&src=&done=https%3A%2F%2Fwww.yahoo.com&display=login';
    private $_yahoo_signup_ajax_url = 'https://login.yahoo.com/account/module/create?validateField=yid';
    private $yahoo_signup_page_content;
    private $yahoo_signup_page_headers;

    private $status = array();

    public function __construct($email = null, $verifier_email = null, $port = 25){
		$this->debug = array();
		$this->debug_raw = array();

		if(!is_null($email) && !is_null($verifier_email)){
			$this->set_email($email);
			$this->set_verifier_email($verifier_email);
		}

		$this->set_port($port);
    }

	public function set_verifier_email($email){$this->verifier_email = $email;}
	public function get_verifier_email(){return $this->verifier_email;}

	public function set_email($email){$this->email = $email;}
	public function get_email(){return $this->email;}

	public function set_port($port){$this->port = $port;}
	public function get_port(){return $this->port;}

	public function change_port($type){
		$type = strtolower((string)$type);
		if($type == "smtp" or $type == "gmail" or $type == "mynet"){$this->port = 587;}
		if($type == "msn" or $type == "live" or $type == "hotmail" or $type == "yahoo"){$this->port = 465;}
		if($type == "pop3"){$this->port = 110;} if($type == "imap"){$this->port = 143;}
	}

	public function validate(){
		if (!filter_var($this->email, FILTER_VALIDATE_EMAIL)) {
			$status['validate'] = false;
			return false;
		}
		$status['validate'] = true;
		return true;
	}

	public function get_domain(){
		$arr = explode("@", $this->email);
		$domain = array_slice($arr, -1);
	  	$this->domain = $domain[0];

		return $this->domain;
	}

	public function get_ip(){
		$this->ip = (string)filter_var($this->domain, FILTER_VALIDATE_IP);
		return $this->ip;
	}

	private function connect_mx(){
		$this->connect = @fsockopen($this->mx, $this->port);
    }

	private function find_mx() {
		$domain = $this->get_domain($this->email);
		$mx_ip = false;

		$domain = ltrim($domain, "[");
		$domain = rtrim($domain, "]");

		if("IPv6:" == substr($domain, 0, strlen("IPv6:"))) {
			$domain = substr($domain, strlen("IPv6") + 1);
		}

		$mxhosts = array();

		if(filter_var($domain, FILTER_VALIDATE_IP)){
			$mx_ip = $domain;
		}else{
			getmxrr($domain, $mxhosts, $mxweight);
		}

		if(!empty($mxhosts)){
			$mx_ip = $mxhosts[array_search(min($mxweight), $mxweight)];
		}else{
			$record_a;
			if(filter_var($domain, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)){
				$record_a = dns_get_record($domain, DNS_A);
			}
			elseif(filter_var($domain, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)){
				$record_a = dns_get_record($domain, DNS_AAAA);
			}
			if(!empty($record_a)){
				$mx_ip = $record_a[0]['ip'];
			}
		}
		$this->mx = $mx_ip;
	}

	public function verify(){
		$is_valid = false;

		$domain = $this->get_domain($this->email);
		if(strtolower($domain) == 'yahoo.com') {
			$is_valid = $this->validate_yahoo();
		}else{
			$this->find_mx();
			if(!$this->mx) return $is_valid;

	        //connect sw
	        $this->connect_mx();
	        if(!$this->connect) return $is_valid;

	        if(preg_match("/^220/i", $out = fgets($this->connect))){
	        	//Got a 220 response. Sending HELO...
	        	fputs ($this->connect , "HELO ".$this->get_domain($this->verifier_email)."\r\n");
	        	$out = fgets ($this->connect);

	        	//Sending MAIL FROM...
	        	fputs($this->connect , "MAIL FROM: <".$this->verifier_email.">\r\n");
      			$from = fgets($this->connect);

      			//Sending RCPT TO...
      			fputs($this->connect , "RCPT TO: <".$this->email.">\r\n");
      			$to = fgets($this->connect);

      			//Sending QUIT...
      			$quit = fputs ($this->connect , "QUIT");
      			fclose($this->connect);

      			//Looking for 250 response...
      			if(!preg_match("/^250/i", $from) || !preg_match("/^250/i", $to)){
		            $is_valid = false; //Not found! Email is invalid
	          	}else{
		            $is_valid = true; //Found! Email is valid
		        }
	        }
		}
		return $is_valid;
	}

	private function validate_yahoo(){
		$this->fetch_yahoo_signup_page();

		$cookies = $this->get_yahoo_cookies();
		$fields = $this->get_yahoo_fields();

		$fields['yid'] = str_replace('@yahoo.com', '', strtolower($this->email));
		$response = $this->request_yahoo_ajax($cookies, $fields);

		$response_errors = json_decode($response, true)['errors'];

		foreach($response_errors as $err){
			if($err['name'] == 'yid' && $err['error'] == 'IDENTIFIER_EXISTS'){
				return true;
			}
		}
		return false;
    }

    private function fetch_yahoo_signup_page(){
		$this->yahoo_signup_page_content = file_get_contents($this->_yahoo_signup_page_url);
		if($this->yahoo_signup_page_content === false){
			die('Cannot not load the sign up page.');
		}else{
			$this->yahoo_signup_page_headers = $http_response_header;
		}
    }
    private function get_yahoo_cookies(){
		if($this->yahoo_signup_page_content !== false){
			$cookies = array();
			foreach ($this->yahoo_signup_page_headers as $hdr) {
				if (preg_match('/^Set-Cookie:\s*(.*?;).*?$/', $hdr, $matches)) {
					$cookies[] = $matches[1];
				}
			}
			if(count($cookies) > 0){
				return $cookies;
			}
		}
		return false;
    }
    private function get_yahoo_fields(){
		$dom = new DOMDocument();
		$fields = array();
		if(@$dom->loadHTML($this->yahoo_signup_page_content)){
			$xp = new DOMXpath($dom);
			$nodes = $xp->query('//input');
			foreach($nodes as $node){
				$fields[$node->getAttribute('name')] = $node->getAttribute('value');
			}
		}
		return $fields;
    }
    private function request_yahoo_ajax($cookies, $fields){
		$headers = array();
		$headers[] = 'Origin: https://login.yahoo.com';
		$headers[] = 'X-Requested-With: XMLHttpRequest';
		$headers[] = 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36';
		$headers[] = 'content-type: application/x-www-form-urlencoded; charset=UTF-8';
		$headers[] = 'Accept: */*';
		$headers[] = 'Referer: https://login.yahoo.com/account/create?specId=yidReg&lang=en-US&src=&done=https%3A%2F%2Fwww.yahoo.com&display=login';
		$headers[] = 'Accept-Encoding: gzip, deflate, br';
		$headers[] = 'Accept-Language: en-US,en;q=0.8,ar;q=0.6';

		$cookies_str = implode(' ', $cookies);
		$headers[] = 'Cookie: '.$cookies_str;
		$postdata = http_build_query($fields);

		$opts = array('http' => array(
			'method'  => 'POST',
			'header'  => $headers,
			'content' => $postdata
		));

		$context  = stream_context_create($opts);
		$result = file_get_contents($this->_yahoo_signup_ajax_url, false, $context);
		return $result;
    }

	public $WHOIS_SERVER = array(
	   "com" =>  array("whois.verisign-grs.com", "No match for "),
	   "net" =>  array("whois.verisign-grs.com", "No match for "),
	   "org" =>  array("whois.pir.org", "NOT FOUND"),
	);

	public $WHOIS_FILE = null;
	public $timeout = 20;

	public function is_available_domain(){
	    if(!$this->WHOIS_FILE==null) { 
	    	$dom_name = $this->domain;
			$this->WHOIS_SERVER = $this->load_whois_data($this->WHOIS_FILE);
			$domain_name = (($dom_name) ? strtolower($dom_name) : false);
			if (gethostbyname($domain_name) == $domain_name){
				$ext = $this->dom_extension($dom_name);
				if (isset($this->WHOIS_SERVER[$ext][0])) {
					$whois_server = $this->WHOIS_SERVER[$ext][0];
					$Not_Found = $this->WHOIS_SERVER[$ext][1];
					
				}else{exit('Domain extension not Supported!');}
				$OPtest = fsockopen($whois_server, 43, $errno, $errstr, $this->timeout);
					$out = $domain_name . "\r\n";
					fwrite($OPtest, $out);
					$whois = null;
					while (!@feof($OPtest)) { 
						$whois .= fgets($OPtest, 128); 
					}
					fclose($OPtest);
					if (strpos($whois,$Not_Found)) return TRUE; 
					else  return FALSE;
			 } else {return FALSE;}
	   }else { exit('Whois Files Not Found!'); }
	}
	
	private function load_whois_data($sorce=false){
		if($sorce) {
		if(file_exists($sorce)){
			include $sorce;
			if(isset($WHOIS_SERVER) && is_array($WHOIS_SERVER)) return $WHOIS_SERVER;			 
			else exit('WHOIS_SERVER MUST BE AN ARRAY');
		}
		else{exit('Whois Server File "'.$sorce.'" Not Found');}
		}else exit('Whois Server Not Defined');
	}
	
	private function dom_extension($domain_name){
		$Xs = explode('.', $domain_name);
		if(count($Xs) === 0) { throw new Exception('Invalid domain extension'); }
		return end($Xs);
	}

	public function is_rfc822($options=array()){
		$email = $this->email;
		$defaults = array(
			'allow_comments'	=> true,
			'public_internet'	=> true,
		);
		$opts = array();
		foreach ($defaults as $k => $v) $opts[$k] = isset($options[$k]) ? $options[$k] : $v;
		$options = $opts;

		$no_ws_ctl	= "[\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x7f]";
		$alpha		= "[\\x41-\\x5a\\x61-\\x7a]";
		$digit		= "[\\x30-\\x39]";
		$cr		= "\\x0d";
		$lf		= "\\x0a";
		$crlf		= "(?:$cr$lf)";

		$obs_char	= "[\\x00-\\x09\\x0b\\x0c\\x0e-\\x7f]";
		$obs_text	= "(?:$lf*$cr*(?:$obs_char$lf*$cr*)*)";
		$text		= "(?:[\\x01-\\x09\\x0b\\x0c\\x0e-\\x7f]|$obs_text)";

		$text		= "(?:$lf*$cr*$obs_char$lf*$cr*)";
		$obs_qp		= "(?:\\x5c[\\x00-\\x7f])";
		$quoted_pair	= "(?:\\x5c$text|$obs_qp)";

		$wsp		= "[\\x20\\x09]";
		$obs_fws	= "(?:$wsp+(?:$crlf$wsp+)*)";
		$fws		= "(?:(?:(?:$wsp*$crlf)?$wsp+)|$obs_fws)";
		$ctext		= "(?:$no_ws_ctl|[\\x21-\\x27\\x2A-\\x5b\\x5d-\\x7e])";
		$ccontent	= "(?:$ctext|$quoted_pair)";
		$comment	= "(?:\\x28(?:$fws?$ccontent)*$fws?\\x29)";
		$cfws		= "(?:(?:$fws?$comment)*(?:$fws?$comment|$fws))";

		$outer_ccontent_dull	= "(?:$fws?$ctext|$quoted_pair)";
		$outer_ccontent_nest	= "(?:$fws?$comment)";
		$outer_comment		= "(?:\\x28$outer_ccontent_dull*(?:$outer_ccontent_nest$outer_ccontent_dull*)+$fws?\\x29)";

		$atext		= "(?:$alpha|$digit|[\\x21\\x23-\\x27\\x2a\\x2b\\x2d\\x2f\\x3d\\x3f\\x5e\\x5f\\x60\\x7b-\\x7e])";
		$atom		= "(?:$cfws?(?:$atext)+$cfws?)";

		$qtext		= "(?:$no_ws_ctl|[\\x21\\x23-\\x5b\\x5d-\\x7e])";
		$qcontent	= "(?:$qtext|$quoted_pair)";
		$quoted_string	= "(?:$cfws?\\x22(?:$fws?$qcontent)*$fws?\\x22$cfws?)";

		$quoted_string	= "(?:$cfws?\\x22(?:$fws?$qcontent)+$fws?\\x22$cfws?)";
		$word		= "(?:$atom|$quoted_string)";

		$obs_local_part	= "(?:$word(?:\\x2e$word)*)";
		$obs_domain	= "(?:$atom(?:\\x2e$atom)*)";

		$dot_atom_text	= "(?:$atext+(?:\\x2e$atext+)*)";
		$dot_atom	= "(?:$cfws?$dot_atom_text$cfws?)";

		$dtext		= "(?:$no_ws_ctl|[\\x21-\\x5a\\x5e-\\x7e])";
		$dcontent	= "(?:$dtext|$quoted_pair)";
		$domain_literal	= "(?:$cfws?\\x5b(?:$fws?$dcontent)*$fws?\\x5d$cfws?)";

		$local_part	= "(($dot_atom)|($quoted_string)|($obs_local_part))";
		$domain		= "(($dot_atom)|($domain_literal)|($obs_domain))";
		$addr_spec	= "$local_part\\x40$domain";

		if (strlen($email) > 254) return 0;
		if ($options['allow_comments']){
			$email = $this->email_strip_comments($outer_comment, $email, "(x)");
		}

		if (!preg_match("!^$addr_spec$!", $email, $m)){
			return 0;
		}
		$bits = array(
			'local'			=> isset($m[1]) ? $m[1] : '',
			'local-atom'		=> isset($m[2]) ? $m[2] : '',
			'local-quoted'		=> isset($m[3]) ? $m[3] : '',
			'local-obs'		=> isset($m[4]) ? $m[4] : '',
			'domain'		=> isset($m[5]) ? $m[5] : '',
			'domain-atom'		=> isset($m[6]) ? $m[6] : '',
			'domain-literal'	=> isset($m[7]) ? $m[7] : '',
			'domain-obs'		=> isset($m[8]) ? $m[8] : '',
		);

		if ($options['allow_comments']){
			$bits['local']	= $this->email_strip_comments($comment, $bits['local']);
			$bits['domain']	= $this->email_strip_comments($comment, $bits['domain']);
		}

		if (strlen($bits['local']) > 64) return 0;
		if (strlen($bits['domain']) > 255) return 0;

		if (strlen($bits['domain-literal'])){
			$Snum			= "(\d{1,3})";
			$IPv4_address_literal	= "$Snum\.$Snum\.$Snum\.$Snum";
			$IPv6_hex		= "(?:[0-9a-fA-F]{1,4})";
			$IPv6_full		= "IPv6\:$IPv6_hex(?:\:$IPv6_hex){7}";
			$IPv6_comp_part		= "(?:$IPv6_hex(?:\:$IPv6_hex){0,7})?";
			$IPv6_comp		= "IPv6\:($IPv6_comp_part\:\:$IPv6_comp_part)";
			$IPv6v4_full		= "IPv6\:$IPv6_hex(?:\:$IPv6_hex){5}\:$IPv4_address_literal";
			$IPv6v4_comp_part	= "$IPv6_hex(?:\:$IPv6_hex){0,5}";
			$IPv6v4_comp		= "IPv6\:((?:$IPv6v4_comp_part)?\:\:(?:$IPv6v4_comp_part\:)?)$IPv4_address_literal";
			if (preg_match("!^\[$IPv4_address_literal\]$!", $bits['domain'], $m)){
				if (intval($m[1]) > 255) return 0;
				if (intval($m[2]) > 255) return 0;
				if (intval($m[3]) > 255) return 0;
				if (intval($m[4]) > 255) return 0;
			}else{
				while (1){
					if (preg_match("!^\[$IPv6_full\]$!", $bits['domain'])){
						break;
					}
					if (preg_match("!^\[$IPv6_comp\]$!", $bits['domain'], $m)){
						list($a, $b) = explode('::', $m[1]);
						$folded = (strlen($a) && strlen($b)) ? "$a:$b" : "$a$b";
						$groups = explode(':', $folded);
						if (count($groups) > 7) return 0;
						break;
					}
					if (preg_match("!^\[$IPv6v4_full\]$!", $bits['domain'], $m)){
						if (intval($m[1]) > 255) return 0;
						if (intval($m[2]) > 255) return 0;
						if (intval($m[3]) > 255) return 0;
						if (intval($m[4]) > 255) return 0;
						break;
					}
					if (preg_match("!^\[$IPv6v4_comp\]$!", $bits['domain'], $m)){
						list($a, $b) = explode('::', $m[1]);
						$b = substr($b, 0, -1); # remove the trailing colon before the IPv4 address
						$folded = (strlen($a) && strlen($b)) ? "$a:$b" : "$a$b";
						$groups = explode(':', $folded);
						if (count($groups) > 5) return 0;
						break;
					}
					return 0;
				}
			}			
		}else{
			$labels = explode('.', $bits['domain']);
			if ($options['public_internet']){
				if (count($labels) == 1) return 0;
			}

			foreach ($labels as $label){
				if (strlen($label) > 63) return 0;
				if (substr($label, 0, 1) == '-') return 0;
				if (substr($label, -1) == '-') return 0;
			}

			if ($options['public_internet']){
				if (preg_match('!^[0-9]+$!', array_pop($labels))) return 0;
			}
		}
		return 1;
	}

	private function email_strip_comments($comment, $email, $replace=''){
		while (1){
			$new = preg_replace("!$comment!", $replace, $email);
			if (strlen($new) == strlen($email)){
				return $email;
			}
			$email = $new;
		}
	}
}


// Example Using

$evv = new EmailVV("test@gmail.com","fatihmertdogancan@hotmail.com");

// Regexp Control (Standart PHP Filter) @return bool
$evv->validate();

// Whois Domain Control  @return bool
$evv->is_available_domain();

// Verify, Default port is 25  @return bool
$evv->verify(); 

// You can change port, example: smtp
$evv->change_port("SMTP");		// [SMTP,GMAIL,MYNET,MSN,LIVE,HOTMAIL,YAHOO,POP3,IMAP]
$evv->verify(); //SMTP verify

// or Default port set
$evv->set_port(587);
$evv->verify(); //SMTP verify

// Validate RFCs 822, 2822, 5322
$evv->is_rfc822();




?>
