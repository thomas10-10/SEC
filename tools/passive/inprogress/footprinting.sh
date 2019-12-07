# get footprinting from PCAP
#!/bin/bash

rm -rf /SEC/private* /SEC/public*
touch /SEC/private-clients.tmp /SEC/private-servers.tmp /SEC/public-clients.tmp /SEC/public-servers.tmp /SEC/private-clients /SEC/private-servers /SEC/public-clients /SEC/public-servers

filePCAP="$1"

############################
#  GET IP                  #
############################
> /SEC/src.ip
tshark -r $filePCAP -E separator=" " -T fields  -Y"arp" -e arp.src.proto_ipv4 >> /SEC/src.ip
tshark -r $filePCAP -E separator=" " -T fields  -Y"arp && arp.opcode="2" " -e arp.dst.proto_ipv4 >> /SEC/src.ip
#tshark -r $filePCAP -E separator=" " -T fields  -Y"icmp" -e ip.src >> /SEC/src.ip
tshark -r $filePCAP -E separator=" " -T fields  -Y"icmp" -e ip.dst >> /SEC/src.ip
tshark -r $filePCAP -E separator=" " -T fields  -Y"udp" -e ip.src -e udp.srcport >> /SEC/src.ip
tshark -r $filePCAP -E separator=" " -T fields  -Y"udp" -e ip.dst -e udp.dstport >> /SEC/src.ip
tshark -r $filePCAP -E separator=" " -T fields  -Y"tcp" -e ip.src -e tcp.srcport>> /SEC/src.ip
tshark -r $filePCAP -E separator=" " -T fields  -Y"tcp" -e ip.dst -e tcp.dstport >> /SEC/src.ip

############################
# SPLIT     PUBLIC/PRIVATE #
############################
#| 
#| 192.168.0.0/16 192.168.0.0 - 192.168.255.255 | 172.16.0.0/12  172.16.0.0 - 172.31.255.255 10.0.0.0/8 10.0.0.0 - 10.255.255.255
#|

regex192='^192\.168\.[0-2]?[0-9]?[0-9]\.[0-2]?[0-9]?[0-9].*'
regex172='^172\.(16|17|18|19|20|21|22|23|24|25|26|27|28|29|30|31)\..*'
regex10='^10\..*'

#Creation fichiers pc private
cat /SEC/src.ip | grep -E -e "$regex192" -e "$regex172" -e "$regex10"  | sort -n | uniq  > /SEC/private
#cat /SEC/$1 | grep -o  "ttl\s[0-9]*\|[0-9]*\.[0-9]*\.[0-9]*\.[0-9]*\.*[0-9]*" | grep -E -e "$regex192" -e "$regex172" -e "$regex10"  | sort -n | uniq  > /SEC/private

#Creation fichiers pc public
cat /SEC/src.ip | grep -E -v -e "$regex192" -e "$regex172" -e "$regex10" | sort -n | uniq > /SEC/public
#cat /SEC/$1 | grep -o  "ttl\s[0-9]*\|[0-9]*\.[0-9]*\.[0-9]*\.[0-9]*\.*[0-9]*" | grep -E -v -e "$regex192" -e "$regex172" -e "$regex10" -e "ttl*" | sort -n | uniq > /SEC/public

##############################
# REPARTITION CLIENT/SERVER  #
##############################
#|
#|
#| 49152-65535 60000-61000 64738 48654-48999 1024-49151
#|

for site in private public
do
	while read i
	do
		port=`echo $i | awk '{ print $2 }' `
		if [ ! "$port" == "" ] ; then
		echo $port

			if  ( [[ "$port" -ge "49152" ]] &&  [[ "$port" -le "65535" ]] ) || ( [[ "$port" -ge "48654" ]] &&  [[ "$port" -le "48999" ]] ) ||  ( [[ "$port" -ge "1024" ]] &&  [[ "$port" -le "49151" ]] ) ; then
				echo "$i" | awk '{ print $1 }'  >> /SEC/"$site"-clients.tmp
			else
				echo "$i" | awk '{ print $1 }'  >> /SEC/"$site"-servers.tmp

			fi

		else
			echo "$i" >> /SEC/"$site"-clients.tmp


		fi
	
		cat /SEC/"$site"-clients.tmp | uniq > /SEC/"$site"-clients
		cat /SEC/"$site"-servers.tmp | uniq > /SEC/"$site"-servers
	done < /SEC/"$site"
done


###################
# GET INFOS OF IP #
###################

function getETH(){
	#$1 IP
	res=`tshark -r $filePCAP -Y"ip.src=="$1""  -T fields -e eth.src | uniq`
	res+=" "`tshark -r $filePCAP -Y"ip.dst=="$1""  -T fields -e eth.dst | uniq`
	res+=" "`tshark -r $filePCAP -Y"arp.src.proto_ipv4=="$1""  -T fields -e arp.src.hw_mac | uniq`
	res+=" "`tshark -r $filePCAP -Y"arp.dst.proto_ipv4=="$1" && arp.opcode="2" "  -T fields -e arp.dst.hw_mac | uniq`
	res=`echo $res | sed s"/\s/\n/"g | uniq`
	# rajouter le protocol arp
	echo $res
}
function getNAME(){
	#$1 IP
	echo empty

}
function getTTL(){
	echo empty
}
function getWinTCP(){
	echo empty
}
function getPORTS(){
	res=`tshark -r $filePCAP -Y "tcp" -Y"ip.src=="$1""   -T fields -e tcp.srcport | uniq`
	res+=" "`tshark -r $filePCAP -Y "udp" -Y"ip.src=="$1""   -T fields -e udp.srcport | uniq`
	res=`echo $res | sed s"/\s/\n/"g | uniq`
	echo $res
}
function Count(){

	tshark -r /SEC/servers.packet -Y "tcp" -Y"ip.dst=="216.58.204.110"" -E separator=":"  -T fields -e ip.src -e tcp.dstport | uniq -c | awk '{ print "N"$1":"$2 }'  
	#N1:192.34.34.21:443
	#N2:194.23.23.12:443

}


#PRIVATE IP

#PUBLIC IP
index=0
> /SEC/view2.tmp
for site in  public private	
do
	[[ "$site" == publick ]] && { echo "PUBLIC # # NAME" ;}

	for type in clients servers
	do
		echo "${type}IP ETH NAME PORTS" >> /SEC/view2.tmp
		
		end=`wc -l /SEC/${site}-${type} | cut -f1 -d" " `
		for num in `seq 1 $end`
		do
			#let index++
			#name=$site$type_$index
			#declare -A $name
			
			IP="`cat /SEC/${site}-${type} | head -n${num} | tail -n1`"
			ETH="`getETH $IP`"
			NAME=""
			PORTS=""
			TTL=""
			WinTCP=""
			Count=""
			
			#[[ "${type}" == "client" ]] && { Agent="" ; }
			[[ "${type}" == "servers" ]] && { PORTS="`getPORTS $IP`" ; }

			# 1IP 2NAME 3TTL 4TCPFRAME 1IP 2NAME 3TTL 4TCPFRAME 5PORT 
			var1=${IP:=_}
			var2=${ETH:=_}
			var3=${NAME:=_}
			var4=${PORTS:=_}

			echo "$var1 $var2 $var3 $var4" >> /SEC/view2.tmp


				
			
		done
		

	done

	[[ "$site" == public ]] && echo "### ### ### ###" >> /SEC/view2.tmp

done

column -t /SEC/view2.tmp 

exit 0

#ANCIENT VIEW
> /SEC/view.final
for site in  public private
do
echo "Hosts # # # | Services # # # #" >> /SEC/view.final
echo "IP Name ttl Tcpframe  |  IP Name ttl Tcpframe port" >> /SEC/view.final


cat /SEC/${site}-clients |  cut -f1,2,3,4 -d"." | uniq > /SEC/${site}-clients-lec
cp /SEC/${site}-servers /SEC/${site}-servers-lec


	if [[ "`wc -l /SEC/${site}-clients-lec | cut -f1 -d" " `" -ge "`wc -l /SEC/${site}-servers-lec | cut -f1 -d" " `" ]] ; then

		end=`wc -l /SEC/${site}-clients-lec | cut -f1 -d" " `
		min=`wc -l /SEC/${site}-servers-lec | cut -f1 -d" " `
		let "to=$end-$min"
		#echo TOTAL $to
		for (( i=1;i<=$to;i++ ))
		do
			echo "0" >> /SEC/${site}-servers-lec 
		done
	else
		end=`wc -l /SEC/${site}-servers-lec | cut -f1 -d" " `
		min=`wc -l /SEC/${site}-clients-lec | cut -f1 -d" " `
		let "to=$end-$min"
		#echo TOTAL $to
		for (( i=1;i<=$to;i++ ))
		do
			echo "0" >> /SEC/${site}-clients-lec
		done


	fi
	for i in `seq 1 $end`
	do
		lecIPc="`cat /SEC/${site}-clients-lec | head -n$i | tail -n1`"
		lecIPs="`cat /SEC/${site}-servers-lec | head -n$i | tail -n1`"
		
		IPc=""
		NAMEc=""
		TTLc=""
		TCPFRAMEc=""

		IPs=""
		NAMEs=""
		TTLs=""
		TCPFRAMEs=""


		if ! [ "$lecIPc" == "0" ] ; then
			IPc=$lecIPc
			NAMEip=`echo $IPc | cut -f1,2,3,4 -d"." `	
			NAMEc=NONE
		 	
		fi
		
		if ! [ "$lecIPs" == "0" ] ; then

			IPs=$lecIPs	
			NAMEs=NONE		
			NAMEip=`echo $IPs | cut -f1,2,3,4 -d"." `	
			NAMEs=`nslookup	$NAMEip | grep name | cut -f2 -d"="`
		 	

		fi


		# 1IP 2NAME 3TTL 4TCPFRAME 1IP 2NAME 3TTL 4TCPFRAME 5PORT 
		EXTc1=${IPc:=_}
		EXTc2=${NAMEc:=_}
		EXTc3=${TTLc:=_}
		EXTc4=${TCPFRAMEc:=_}

		EXTs1=${IPs:=_}
		EXTs2=${NAMEs:=_}
		EXTs3=${TTLs:=_}
		EXTs4=${TCPFRAMEs:=_}
		EXTs5=${PORTs:=_}
		echo "$EXTc1 $EXTc2 $EXTc3 $EXTc4 | $EXTs1 $EXTs2 $EXTs3 $EXTs4 $EXTs5" >> /SEC/view.final

	done
	if [[ $site == public ]] ; then
		echo "---------------  ----------------  ---     --------  -  ---------------  ------------  ----    ---------  ----" >> /SEC/view.final	
	fi
done

column -t /SEC/view.final
