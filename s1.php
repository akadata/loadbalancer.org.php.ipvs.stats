<?php

/* 	I expect the use of an SSH Key here, I will not code for passwords when used with SSH
   	If this all works remotely then it will work locally on a loadbalancer.org appliance. 

   	For now its single appliance, one day the two lines above will apply. 

   	...

   	Ideas:		add failed heakthcheck times, ie(monitor ldirectord.log)
				add ping latency for each real server

	Thoughts:	i made another version which called ipvsadm many times, 
				the script took a few seconds to run with many vips.

				this version is done and output with 100xVIP 4000xRIP
				it takes around 132ms for 272kB 

	
*/
$output="array"; // array,json are valid. 
echo "<pre>";
$cach="false";
$ldirectord=populateXML($cache);
// print_r($ldirectord);
// die();
$reports=array("stats","rate","thresholds","persistent-conn");


foreach($reports as $report) {
	
	$ipvs[$report]["command"][0]="sudo ipvsadm -Ln --".$report." --sort ";
	$ipvs[$report]["command"][0].=" | sed 1d";
}

//print_r($ipvs);


foreach($reports as $report) {
$id=-1;	
	$lvscmd=$ipvs[$report]["command"][0].$ipvs[$report]["command"][1];

	$stats[$report]=trim(shell_exec($lvscmd));
	$stats[$report]=explode("\n",$stats[$report]);

	$viptypes=array("TCP","UDP","FWM","OPS");
 
	$vkeys[$report]=lineparts($stats[$report][0]);
	$rkeys[$report]=lineparts($stats[$report][1]);

	//print_r($rkeys[$report]);
	unset($stats[$report][0]);
	unset($stats[$report][1]);
	//$realc=$vipc=$realt=$vipt=0;
	foreach($stats[$report] as $key=>$stat) {	
		unset($stats[$report][$key]);
		$sta=lineparts($stat);
		// print_r($sta);
		//if($report=="ipvsadm") die();
		if(in_array($sta[0],$viptypes) && $sta[1]!=" ->") {
			$id++;
			$realid=0;
			$type=$sta[0];
			
			
			foreach($sta as $skey=>$sval) {
						
				if($report =="ipvsadm" ||$report =="persistent-conn" || $report =="thresholds") {
					continue;
				}					
				$lvs[$type]["VIP"][$id]["report"][$vkeys[$report][$skey]]=$sval;
			}	

			if($type=="FWM") {
				foreach($ldirectord as $ldk=>$ldv) {
					if($sta[1]==$ldv["firewallmark"]) {
						if($lvs[$type]["VIP"][$id]["info"]["firewallmark"]==$ldv["firewallmark"]) continue;
						$lvs[$type]["VIP"][$id]["info"]["firewallmark"]==$ldv["firewallmark"];
						$lvs[$type]["VIP"][$id]["info"]["label"]=$ldv["label"];
						$lvs[$type]["VIP"][$id]["info"]["forwardingmethod"]=$ldv["forwardingmethod"];
						$lvs[$type]["VIP"][$id]["info"]["protocol"]=$ldv["protocol"];
						$lvs[$type]["VIP"][$id]["info"]["server"]=$ldv["server"];
						$lvs[$type]["VIP"][$id]["info"]["ports"]=$ldv["ports"];
						$lvs[$type]["VIP"][$id]["info"]["scheduler"]=$ldv["scheduler"];
						$f=1;

					}
				}
			}

			if($type=="TCP" || $type=="UDP") {
				$ipport=explode(":",$lvs[$type]["VIP"][$id]["report"]["LocalAddress:Port"]);
				foreach($ldirectord as $ldk=>$ldv) {
					//print_r($ldv);
					if($ipport[0]==$ldv["server"] && $ipport[1]==$ldv["ports"]) {
						if($lvs[$type]["VIP"][$id]["info"]["server"]==$ldv["server"] && $lvs[$type]["VIP"][$id]["info"]["ports"]==$ldv["ports"]) continue;				
						$lvs[$type]["VIP"][$id]["info"]["label"]=$ldv["label"];
						$lvs[$type]["VIP"][$id]["info"]["forwardingmethod"]=$ldv["forwardingmethod"];
						$lvs[$type]["VIP"][$id]["info"]["protocol"]=$ldv["protocol"];
						$lvs[$type]["VIP"][$id]["info"]["server"]=$ldv["server"];
						$lvs[$type]["VIP"][$id]["info"]["ports"]=$ldv["ports"];
						$lvs[$type]["VIP"][$id]["info"]["scheduler"]=$ldv["scheduler"];
						$f=1;
					}
				}
			}

		} else {
			$ipport=explode(":",$sta[1]);
			if($ipport[0]=="127.0.0.1") {
				$lvs[$type]["VIP"][$id]["RIP"][$realid]["info"]["label"]="fallbackserver";
			}
			$lvs[$type]["VIP"][$id]["RIP"][$realid]["info"]["label"]="";
			// print_r($sta);
			foreach($sta as $skey=>$sval) {		
				if($vkeys[$report][$skey]=="Prot") continue;
				$lvs[$type]["VIP"][$id]["RIP"][$realid]["reports"][$vkeys[$report][$skey]]=$sval;		
			}	
			$realid++;
			}	
		}
	}

	switch($output){
		case "array":
			print_r($lvs);
		break; 
		case "json": 	
		echo json_encode($lvs);
		break;
		default:
	}


function lineparts($line) {
	$results=preg_split('/\s+/', $line, NULL, PREG_SPLIT_NO_EMPTY);
	return $results;
}



function xmlToArray($xml, $ns = null)
{
	$a = array();
	for($xml->rewind(); $xml->valid(); $xml->next()) {
		$key = $xml->key();
		if(!isset($a[$key])) {
			$a[$key] = array();
			$i       = 0;
		} else {
			$i = count($a[$key]);
		}
		$simple = true;
		foreach($xml->current()->attributes() as $k => $v) {
			$a[$key][$i][$k] = (string) $v;
			$simple          = false;
		}
		if($ns) {
			foreach($ns as $nid => $name) {
				foreach ($xml->current()->attributes($name) as $k => $v) {
					$a[$key][$i][$nid . ':' . $k] = (string) $v;
					$simple                       = false;
				}
			}
		}
		if($xml->hasChildren()) {
			if ($simple) {
				$a[$key][$i] = xmlToArray($xml->current(), $ns);
			} else {
				$a[$key][$i]['content'] = xmlToArray($xml->current(), $ns);
			}
		} else {
			if($simple) {
				$a[$key][$i] = strval($xml->current());
			} else {
				$a[$key][$i]['content'] = strval($xml->current());
			}
		}
		$i++;
	}
	return $a;
}



function populateXML($cache) {
	$xmldata="/etc/loadbalancer.org/lb_config.xml";
	$lastmod=date ("YdmHis", filemtime($xmldata));
if((file_get_contents("/dev/shm/lvs.lastmod") !=$lastmod) && ($cache=="true")) {
	if($cache!="true") {
		file_put_contents('/dev/shm/lvs.lastmod', print_r($lastmod, true));
	}
	$xml               = new SimpleXmlIterator($xmldata, null, true);
	$namespaces        = $xml->getNamespaces(true);
	$array               = xmlToArray($xml, $namespaces);
	$virtual=$array["ldirectord"]["0"]["virtual"];
	print_r($virtual);
	foreach($virtual as $id=>$vips) {	
		unset($virtual[$id]["service"]);	
		unset($virtual[$id]["emailalert"]);	
		unset($virtual[$id]["fallback"]);	
		$vip[$id]["label"]=$vips["label"][0];	
		$vip[$id]["protocol"]=strtoupper($vips["protocol"][0]);	
		$vip[$id]["server"]=$vips["server"][0];	
		$vip[$id]["ports"]=$vips["ports"][0];	
		$vip[$id]["forwardingmethod"]=$vips["forwardingmethod"][0];
		$vip[$id]["protocol"]=$vips["protocol"][0];	
		$vip[$id]["server"]=$vips["server"][0];	
		$vip[$id]["ports"]=$vips["ports"][0];	
		$vip[$id]["scheduler"]=$vips["scheduler"][0];
		if(!empty($vips["firewallmark"][0])) {		
			if(is_numeric($vips["firewallmark"][0])) {			
				$vip[$id]["firewallmark"]=$vips["firewallmark"][0];	
			}
		}	

		if(isset($vips['real'])) {		
			foreach($vips['real'] as $rid=>$rip) {			
				$vip[$id]["real"][$rid]["label"]=$rip["label"][0];			
				if(empty($rip["port"][0])) {				
					$rip["port"][0]="0";			
				}			
				$vip[$id]["real"][$rid]["server"]=$rip["server"][0];			
				$vip[$id]["real"][$rid]["port"]=$rip["port"][0];	
			}	
		}
	}
	file_put_contents('/dev/shm/vip.data', serialize($vip));
} else {	
	$vip=unserialize(file_get_contents("/dev/shm/vip.data"));
}
return $vip;
}

