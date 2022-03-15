#!/bin/bash
#set -x

VERSION="$0 (v0.3.2 build date 202203142100)"
DATABASE_VERSION=1
DATADIR="$HOME/.dashcrawler"

# mainnet or testnet
NETWORK="testnet"

testnet_magic="CEE2CAFF"
mainnet_magic="BF0C6BBD"

# Number of seconds since the last check before the crawler will check the node again.
# Seconds * Minutes * hours * days
POLL_TIME=$((60 * 60 * 24 * 1))

# Delete nodes that have not been active DELETE_TIME seconds.
DELETE_TIME=$((60 * 60 * 24 * 5))

usage(){
	text="$VERSION\n"
	text+="This program will crawl over the dash network and find all the\n"
	text+="full nodes and masternodes and record them to a sqlite database.\n\n"
	text+="Usage: $0 [ options ] [ ip ] [ port ]\n\n"
	text+="Options:\n"
	text+="	-help				This help text.\n"
	text+="	-network [mainnet][testnet]	The network to use.\n"
	text+="	-user-agent [User Agent]	A custom User Agent for the crawler.\n"
	text+="	-protocol [protocol]		The protocol number to use.\n"
	text+="	-datadir [path_to_dir]		The location to save the data in, default location is $DATADIR\n"
	text+="\nSpecifying the [ ip ] and [ port ] is optional for all except the initial run which requires\n"
	text+="an active node to start from.  If no options are given, the crawler\n"
	text+="will search the database and find nodes to traverse from there."
	echo -e "$text"
}

# Parse commandline options and set flags.
while (( $# > 0 ))
do
key="$1"

case $key in
	-h|-help|--help)
		usage
		exit 0
		;;
	-network)
		case $2 in 
			mainnet)
				NETWORK="mainnet"
				;;
			testnet)
				NETWORK="testnet"
				;;
			*)
				echo -e "[$$] Unknown network $2\n[$$] Valid options are mainnet or testnet." >&2
				exit 6
				;;
		esac
		shift;shift
		;;
	-user-agent)
		if (( ${#2} > 255 ));then
			echo -e "[$$] User Agent string cannot be longer than 255 chars." >&2
			exit 14
		fi
		USER_AGENT="$2"
		shift;shift
		;;
	-protocol)
		if ! [[ "$2" =~ ^[0-9]+$ ]];then
			echo -e "[$$] Protocol number be a number eg 70217." >&2
			exit 15
		fi
		PROTOCOL=$2
		shift;shift
		;;
	-datadir)
		DATADIR="$2"
		shift;shift
		;;
	-child)
		CHILD="X"
		shift
		;;
	*)
		# The default case, try to check for an IP or Port and set it, otherwise complain about bad input.
		if [[ "$1" =~ ^(0*(1?[0-9]{1,2}|2([0-4][0-9]|5[0-5]))\.){3}0*(1?[0-9]{1,2}|2([‌​0-4][0-9]|5[0-5]))$ ]];then
			IP="$1"
		elif [[ "$1" =~ ^[0-9]+$ ]] && (($1 >= 0)) && (($1 < 65536));then
			PORT=$1
		else
			echo -e "[$$] $VERSION\n[$$] Unknown parameter $1\n[$$] Please check help page with $0 -help" >&2
			exit 8
		fi
		shift
		;;
esac
done

echo "[$$] Starting $VERSION." >&2

# Sanity check on parameters that work as a pair.
if [[ (-z $IP && ! -z $PORT) || (! -z $IP && -z $PORT) ]];then
	echo "[$$] $IP + $PORT" >&2
	echo -e "[$$] You need to provide both a valid IP address and port number [1-65535].\n[$$] Please check help page with $0 -help." >&2
	exit 9
fi


# Now we are safe to use variables like NETWORK and DATADIR, so let's compute a database_file
DATABASE_FILE="$DATADIR/database/$NETWORK/nodes.db"


# Checks that the required software is installed on this machine.
check_dependencies(){

	bc -v >/dev/null 2>&1 || progs+=" bc"

	nc -h >/dev/null 2>&1 || progs+=" netcat"

	sqlite3 -version >/dev/null 2>&1 || progs+=" sqlite3"


	if [[ -n $progs ]];then
		text="[$$] $VERSION\n[$$] Missing applications on your system, please run\n\n"
		text+="[$$] sudo apt install $progs\n\n[$$] before running this program again."
		echo -e "$text" >&2
		exit 1
	fi
}


make_datadir(){

	if [[ ! -d "$DATADIR" ]];then
		mkdir -p "$DATADIR"/{database/{mainnet,testnet},payloads,dumps,logs}
		if (( $? != 0 ));then
			echo "[$$] Error creating datadir at $DATADIR exiting..." >&2
			exit 2
		fi
	fi
}


create_payloads(){

	# Create the version payload to spoof the dashd service into thinking we are a real node.

	if [[ -n $USER_AGENT ]];then
		ua_hex=$(hexdump -v -e '/1 "%02X"' <<< "$USER_AGENT"|sed 's/..$//g')
		ua_len=$(printf '%02x' ${#USER_AGENT})
		ua_hex=$ua_len$ua_hex
	else
		ua_hex="1468747470733A2F2F6D6E6F77617463682E6F7267"
	fi
	if [[ -n $PROTOCOL ]];then
		version_services=$(printf '%08x' "$PROTOCOL")
		version_services=${version_services:6:2}${version_services:4:2}${version_services:2:2}${version_services:0:2}"0500000000000000"
	else
		version_services="491201000500000000000000"
	fi
	timestamp=$(printf '%08x' "$EPOCHSECONDS")
	timestamp=${timestamp:6:2}${timestamp:4:2}${timestamp:2:2}${timestamp:0:2}"00000000"
	if [[ -n $IP ]];then
		addr_recv_ip_address=$(while IFS='.' read -r a b c d;do printf '%02x%02x%02x%02x' "$a" "$b" "$c" "$d";done <<< "$IP")
		addr_recv_ip_address="050000000000000000000000000000000000FFFF"$addr_recv_ip_address$(printf '%04x' "$PORT")
	else
		addr_recv_ip_address="0500000000000000000000000000000000000000000000000000"
	fi
	nonce=$(printf '%016x' $$)

	# Height is not something we have, but we can guess where it will be at any point in time.
	# Block 1306000 happened at 1594980000 on mainnet and another 2 blocks comes every 315 seconds.
	# So, ((time_now - 1594980000) / 315 * 2) + 1306000 = the current block.
	delta=$((EPOCHSECONDS - 1594980000))
	case $NETWORK in
		mainnet)
			height=$(($(($((delta / 315)) * 2 ))+1306000))
			;;
		testnet)
			height=$(($(($((delta / 315)) * 2 ))+345000))
			;;
		*)
			height=0
			;;
	esac
	height=$(printf '%08x' $height)
	height=${height:6:2}${height:4:2}${height:2:2}${height:0:2}

	vers_payload=$version_services$timestamp$addr_recv_ip_address"0000000000000000000000000000000000000000000000000000"$nonce$ua_hex$height

	# Now create the message header.
	payload_size=$((${#vers_payload} / 2))
	payload_size=$(printf '%08x' $payload_size)
	payload_size=${payload_size:6:2}${payload_size:4:2}${payload_size:2:2}${payload_size:0:2}

	# Use a case to set the network magic.
	case $NETWORK in
		mainnet)
			net_magic=$mainnet_magic
			;;
		testnet)
			net_magic=$testnet_magic
			;;
		*)
			net_magic="00000000"
			;;
	esac

	# Add the command for 'version'
	net_magic_command=$net_magic"76657273696f6e0000000000"

	# Finally compute the double sha256 hash of the payload.
	payload_hash=$(xxd -r -p <<< "$vers_payload"|sha256sum|while read -r a b;do h=$(xxd -r -p <<< "$a"|sha256sum);echo "${h:0:8}";done)

	message_header=$net_magic_command$payload_size$payload_hash

	xxd -r -p <<< "$message_header" >"$DATADIR"/payloads/payload_01.bin
	if (( $? != 0 ));then
		echo "[$$] Unable to create payload into $DATADIR/payloads/payload_01.bin exiting..." >&2
		exit 3
	fi
	xxd -r -p <<< "$vers_payload" >"$DATADIR"/payloads/payload_02.bin

	# Just replay the next two payloads, nothing interesting or dynamic in them.
	xxd -r -p <<< $net_magic"76657261636b000000000000000000005df6e0e2" >"$DATADIR"/payloads/payload_03.bin
	xxd -r -p <<< $net_magic"676574616464720000000000000000005df6e0e2" >"$DATADIR"/payloads/payload_04.bin
}


# A safe wrapper around SQL access to help with contention in concurrent environments.
execute_sql(){

	[[ -z $1 ]] && return
	for((i=1; i<100; i++));do
		sqlite3 "$DATABASE_FILE" <<< "$1" 2>>"$DATADIR"/logs/sqlite.log && return
		retval=$?
		echo "[$$] Failed query attempt number: $i." >>"$DATADIR"/logs/sqlite.log
		delay=1
		# Add extra delay time after every 10 failed shots.
		(($((i % 10)) == 0)) && delay=$((delay+RANDOM%100))
		(($((i % 20)) == 0)) && delay=$((delay+RANDOM%300))
		sleep "$delay"
	done
	echo -e "[$$] The failed query vvvvv\n$1\n[$$] ^^^^^ The above query did not succeed after $i attempts, aborting..." >>"$DATADIR"/logs/sqlite.log
	return $retval
}


initialise_database(){

	if [[ ! -f "$DATABASE_FILE" ]];then
		# Create db objects.
		# DASH_NODES	-	Stores the nodes found on the dash network.
		#			id					-	Just some unique sequence.
		#			ip					-	The IP address mandatory.
		#			port				-	The port number mandatory.
		#			active_YNU			-	Mandatory, choice of 'Y' for confirmed active node, 'N' for confirmed unreachable or inactive node and 'U' for not checked.
		#			last_active_time	-	null if never been active, else the time the node was last seen active.
		#			last_seen_time		-	The last time the nodes had this node in their list of nodes.
		#			checked_time		-	If null, the node has not been verified yet, else store the UNIX Epoch time of check.
		#			check_in_progress_YN-	Only for dealing with concurrency issues.
		#			protocol_version	-	If the node is active record its reported proto_version.
		#			height				-	If the node is active record its reported best height.
		#			user_agent			-	If the node is active record its reported User agent.
		#			masternode_ynu		-	If the node claims to be a masternode.
		# Example: insert into DASH_NODES(ip,port) values('1.2.1.2',65535);
		#
		# The list of nodes can include valid nodes that are not active and never been active, eg full nodes behind a firewall.
		# These will have a recent last_seen_time because the network is still reporting them as valid nodes.
		sql="create table db_version(version integer primary key not null);"
		sql+="insert into db_version values(1);"
		sql+="create table DASH_NODES(id INTEGER PRIMARY KEY ASC NOT NULL, ip TEXT NOT NULL, port INTEGER NOT NULL check(port>=0 and port<65536), active_YNU TEXT DEFAULT 'U' NOT NULL, last_active_time INTEGER,last_seen_time INTEGER, checked_time INTEGER, check_in_progress_YN TEXT DEFAULT 'N', protocol_version INTEGER, height INTEGER, user_agent TEXT, masternode_ynu TEXT DEFAULT 'U' NOT NULL,country_code TEXT);"
		sql+="create unique index idx_ip_port on DASH_NODES(ip,port);"
		sql+="create table country(country_name text not null, country_code text primary key not null);"
		sql+="insert into country(country_name,country_code)values('Afghanistan','AF');"
		sql+="insert into country(country_name,country_code)values('Aland Islands','AX');"
		sql+="insert into country(country_name,country_code)values('Albania','AL');"
		sql+="insert into country(country_name,country_code)values('Algeria','DZ');"
		sql+="insert into country(country_name,country_code)values('American Samoa','AS');"
		sql+="insert into country(country_name,country_code)values('Andorra','AD');"
		sql+="insert into country(country_name,country_code)values('Angola','AO');"
		sql+="insert into country(country_name,country_code)values('Anguilla','AI');"
		sql+="insert into country(country_name,country_code)values('Antarctica','AQ');"
		sql+="insert into country(country_name,country_code)values('Antigua and Barbuda','AG');"
		sql+="insert into country(country_name,country_code)values('Argentina','AR');"
		sql+="insert into country(country_name,country_code)values('Armenia','AM');"
		sql+="insert into country(country_name,country_code)values('Aruba','AW');"
		sql+="insert into country(country_name,country_code)values('Australia','AU');"
		sql+="insert into country(country_name,country_code)values('Austria','AT');"
		sql+="insert into country(country_name,country_code)values('Azerbaijan','AZ');"
		sql+="insert into country(country_name,country_code)values('The Bahamas','BS');"
		sql+="insert into country(country_name,country_code)values('Bahrain','BH');"
		sql+="insert into country(country_name,country_code)values('Bangladesh','BD');"
		sql+="insert into country(country_name,country_code)values('Barbados','BB');"
		sql+="insert into country(country_name,country_code)values('Belarus','BY');"
		sql+="insert into country(country_name,country_code)values('Belgium','BE');"
		sql+="insert into country(country_name,country_code)values('Belize','BZ');"
		sql+="insert into country(country_name,country_code)values('Benin','BJ');"
		sql+="insert into country(country_name,country_code)values('Bermuda','BM');"
		sql+="insert into country(country_name,country_code)values('Bhutan','BT');"
		sql+="insert into country(country_name,country_code)values('Bolivia','BO');"
		sql+="insert into country(country_name,country_code)values('Saba','BQ');"
		sql+="insert into country(country_name,country_code)values('Bosnia and Herzegovina','BA');"
		sql+="insert into country(country_name,country_code)values('Botswana','BW');"
		sql+="insert into country(country_name,country_code)values('Bouvet Island','BV');"
		sql+="insert into country(country_name,country_code)values('Brazil','BR');"
		sql+="insert into country(country_name,country_code)values('British Indian Ocean Territory','IO');"
		sql+="insert into country(country_name,country_code)values('Brunei','BN');"
		sql+="insert into country(country_name,country_code)values('Bulgaria','BG');"
		sql+="insert into country(country_name,country_code)values('Burkina Faso','BF');"
		sql+="insert into country(country_name,country_code)values('Burundi','BI');"
		sql+="insert into country(country_name,country_code)values('Cape Verde','CV');"
		sql+="insert into country(country_name,country_code)values('Cambodia','KH');"
		sql+="insert into country(country_name,country_code)values('Cameroon','CM');"
		sql+="insert into country(country_name,country_code)values('Canada','CA');"
		sql+="insert into country(country_name,country_code)values('Cayman Islands','KY');"
		sql+="insert into country(country_name,country_code)values('Central African Republic','CF');"
		sql+="insert into country(country_name,country_code)values('Chad','TD');"
		sql+="insert into country(country_name,country_code)values('Chile','CL');"
		sql+="insert into country(country_name,country_code)values('China','CN');"
		sql+="insert into country(country_name,country_code)values('Christmas Island','CX');"
		sql+="insert into country(country_name,country_code)values('Cocos (Keeling) Islands','CC');"
		sql+="insert into country(country_name,country_code)values('Colombia','CO');"
		sql+="insert into country(country_name,country_code)values('Comoros','KM');"
		sql+="insert into country(country_name,country_code)values('Democratic Republic of the Congo','CD');"
		sql+="insert into country(country_name,country_code)values('Congo','CG');"
		sql+="insert into country(country_name,country_code)values('Cook Islands','CK');"
		sql+="insert into country(country_name,country_code)values('Costa Rica','CR');"
		sql+="insert into country(country_name,country_code)values('Ivory Coast','CI');"
		sql+="insert into country(country_name,country_code)values('Croatia','HR');"
		sql+="insert into country(country_name,country_code)values('Cuba','CU');"
		sql+="insert into country(country_name,country_code)values('Curacao','CW');"
		sql+="insert into country(country_name,country_code)values('Cyprus','CY');"
		sql+="insert into country(country_name,country_code)values('Czech Republic','CZ');"
		sql+="insert into country(country_name,country_code)values('Denmark','DK');"
		sql+="insert into country(country_name,country_code)values('Djibouti','DJ');"
		sql+="insert into country(country_name,country_code)values('Dominica','DM');"
		sql+="insert into country(country_name,country_code)values('Dominican Republic','DO');"
		sql+="insert into country(country_name,country_code)values('Ecuador','EC');"
		sql+="insert into country(country_name,country_code)values('Egypt','EG');"
		sql+="insert into country(country_name,country_code)values('El Salvador','SV');"
		sql+="insert into country(country_name,country_code)values('Equatorial Guinea','GQ');"
		sql+="insert into country(country_name,country_code)values('Eritrea','ER');"
		sql+="insert into country(country_name,country_code)values('Estonia','EE');"
		sql+="insert into country(country_name,country_code)values('Eswatini','SZ');"
		sql+="insert into country(country_name,country_code)values('Ethiopia','ET');"
		sql+="insert into country(country_name,country_code)values('Falkland Islands','FK');"
		sql+="insert into country(country_name,country_code)values('Faroe Islands','FO');"
		sql+="insert into country(country_name,country_code)values('Fiji','FJ');"
		sql+="insert into country(country_name,country_code)values('Finland','FI');"
		sql+="insert into country(country_name,country_code)values('France','FR');"
		sql+="insert into country(country_name,country_code)values('French Guiana','GF');"
		sql+="insert into country(country_name,country_code)values('French Polynesia','PF');"
		sql+="insert into country(country_name,country_code)values('French Southern and Antarctic Lands','TF');"
		sql+="insert into country(country_name,country_code)values('Gabon','GA');"
		sql+="insert into country(country_name,country_code)values('Gambia','GM');"
		sql+="insert into country(country_name,country_code)values('Georgia','GE');"
		sql+="insert into country(country_name,country_code)values('Germany','DE');"
		sql+="insert into country(country_name,country_code)values('Ghana','GH');"
		sql+="insert into country(country_name,country_code)values('Gibraltar','GI');"
		sql+="insert into country(country_name,country_code)values('Greece','GR');"
		sql+="insert into country(country_name,country_code)values('Greenland','GL');"
		sql+="insert into country(country_name,country_code)values('Grenada','GD');"
		sql+="insert into country(country_name,country_code)values('Guadeloupe','GP');"
		sql+="insert into country(country_name,country_code)values('Guam','GU');"
		sql+="insert into country(country_name,country_code)values('Guatemala','GT');"
		sql+="insert into country(country_name,country_code)values('Guernsey','GG');"
		sql+="insert into country(country_name,country_code)values('Guinea','GN');"
		sql+="insert into country(country_name,country_code)values('Guinea-Bissau','GW');"
		sql+="insert into country(country_name,country_code)values('Guyana','GY');"
		sql+="insert into country(country_name,country_code)values('Haiti','HT');"
		sql+="insert into country(country_name,country_code)values('Heard Island and McDonald Islands','HM');"
		sql+="insert into country(country_name,country_code)values('Holy See, Vatican','VA');"
		sql+="insert into country(country_name,country_code)values('Honduras','HN');"
		sql+="insert into country(country_name,country_code)values('Hong Kong','HK');"
		sql+="insert into country(country_name,country_code)values('Hungary','HU');"
		sql+="insert into country(country_name,country_code)values('Iceland','IS');"
		sql+="insert into country(country_name,country_code)values('India','IN');"
		sql+="insert into country(country_name,country_code)values('Indonesia','ID');"
		sql+="insert into country(country_name,country_code)values('Iran','IR');"
		sql+="insert into country(country_name,country_code)values('Iraq','IQ');"
		sql+="insert into country(country_name,country_code)values('Ireland','IE');"
		sql+="insert into country(country_name,country_code)values('Isle of Man','IM');"
		sql+="insert into country(country_name,country_code)values('Israel','IL');"
		sql+="insert into country(country_name,country_code)values('Italy','IT');"
		sql+="insert into country(country_name,country_code)values('Jamaica','JM');"
		sql+="insert into country(country_name,country_code)values('Japan','JP');"
		sql+="insert into country(country_name,country_code)values('Jersey','JE');"
		sql+="insert into country(country_name,country_code)values('Jordan','JO');"
		sql+="insert into country(country_name,country_code)values('Kazakhstan','KZ');"
		sql+="insert into country(country_name,country_code)values('Kenya','KE');"
		sql+="insert into country(country_name,country_code)values('Kiribati','KI');"
		sql+="insert into country(country_name,country_code)values('North Korea','KP');"
		sql+="insert into country(country_name,country_code)values('South Korea','KR');"
		sql+="insert into country(country_name,country_code)values('Kuwait','KW');"
		sql+="insert into country(country_name,country_code)values('Kyrgyzstan','KG');"
		sql+="insert into country(country_name,country_code)values('Laos','LA');"
		sql+="insert into country(country_name,country_code)values('Latvia','LV');"
		sql+="insert into country(country_name,country_code)values('Lebanon','LB');"
		sql+="insert into country(country_name,country_code)values('Lesotho','LS');"
		sql+="insert into country(country_name,country_code)values('Liberia','LR');"
		sql+="insert into country(country_name,country_code)values('Libya','LY');"
		sql+="insert into country(country_name,country_code)values('Liechtenstein','LI');"
		sql+="insert into country(country_name,country_code)values('Lithuania','LT');"
		sql+="insert into country(country_name,country_code)values('Luxembourg','LU');"
		sql+="insert into country(country_name,country_code)values('Macau','MO');"
		sql+="insert into country(country_name,country_code)values('North Macedonia','MK');"
		sql+="insert into country(country_name,country_code)values('Madagascar','MG');"
		sql+="insert into country(country_name,country_code)values('Malawi','MW');"
		sql+="insert into country(country_name,country_code)values('Malaysia','MY');"
		sql+="insert into country(country_name,country_code)values('Maldives','MV');"
		sql+="insert into country(country_name,country_code)values('Mali','ML');"
		sql+="insert into country(country_name,country_code)values('Malta','MT');"
		sql+="insert into country(country_name,country_code)values('Marshall Islands','MH');"
		sql+="insert into country(country_name,country_code)values('Martinique','MQ');"
		sql+="insert into country(country_name,country_code)values('Mauritania','MR');"
		sql+="insert into country(country_name,country_code)values('Mauritius','MU');"
		sql+="insert into country(country_name,country_code)values('Mayotte','YT');"
		sql+="insert into country(country_name,country_code)values('Mexico','MX');"
		sql+="insert into country(country_name,country_code)values('Micronesia','FM');"
		sql+="insert into country(country_name,country_code)values('Moldova','MD');"
		sql+="insert into country(country_name,country_code)values('Monaco','MC');"
		sql+="insert into country(country_name,country_code)values('Mongolia','MN');"
		sql+="insert into country(country_name,country_code)values('Montenegro','ME');"
		sql+="insert into country(country_name,country_code)values('Montserrat','MS');"
		sql+="insert into country(country_name,country_code)values('Morocco','MA');"
		sql+="insert into country(country_name,country_code)values('Mozambique','MZ');"
		sql+="insert into country(country_name,country_code)values('Myanmar','MM');"
		sql+="insert into country(country_name,country_code)values('Namibia','NA');"
		sql+="insert into country(country_name,country_code)values('Nauru','NR');"
		sql+="insert into country(country_name,country_code)values('Nepal','NP');"
		sql+="insert into country(country_name,country_code)values('Netherlands','NL');"
		sql+="insert into country(country_name,country_code)values('New Caledonia','NC');"
		sql+="insert into country(country_name,country_code)values('New Zealand','NZ');"
		sql+="insert into country(country_name,country_code)values('Nicaragua','NI');"
		sql+="insert into country(country_name,country_code)values('Niger','NE');"
		sql+="insert into country(country_name,country_code)values('Nigeria','NG');"
		sql+="insert into country(country_name,country_code)values('Niue','NU');"
		sql+="insert into country(country_name,country_code)values('Norfolk Island','NF');"
		sql+="insert into country(country_name,country_code)values('Northern Mariana Islands','MP');"
		sql+="insert into country(country_name,country_code)values('Norway','NO');"
		sql+="insert into country(country_name,country_code)values('Oman','OM');"
		sql+="insert into country(country_name,country_code)values('Pakistan','PK');"
		sql+="insert into country(country_name,country_code)values('Palau','PW');"
		sql+="insert into country(country_name,country_code)values('Palestine','PS');"
		sql+="insert into country(country_name,country_code)values('Panama','PA');"
		sql+="insert into country(country_name,country_code)values('Papua New Guinea','PG');"
		sql+="insert into country(country_name,country_code)values('Paraguay','PY');"
		sql+="insert into country(country_name,country_code)values('Peru','PE');"
		sql+="insert into country(country_name,country_code)values('Philippines','PH');"
		sql+="insert into country(country_name,country_code)values('Pitcairn Islands','PN');"
		sql+="insert into country(country_name,country_code)values('Poland','PL');"
		sql+="insert into country(country_name,country_code)values('Portugal','PT');"
		sql+="insert into country(country_name,country_code)values('Puerto Rico','PR');"
		sql+="insert into country(country_name,country_code)values('Qatar','QA');"
		sql+="insert into country(country_name,country_code)values('Reunion','RE');"
		sql+="insert into country(country_name,country_code)values('Romania','RO');"
		sql+="insert into country(country_name,country_code)values('Russia','RU');"
		sql+="insert into country(country_name,country_code)values('Rwanda','RW');"
		sql+="insert into country(country_name,country_code)values('Saint Barthelemy','BL');"
		sql+="insert into country(country_name,country_code)values('Tristan da Cunha','SH');"
		sql+="insert into country(country_name,country_code)values('Saint Kitts and Nevis','KN');"
		sql+="insert into country(country_name,country_code)values('Saint Lucia','LC');"
		sql+="insert into country(country_name,country_code)values('Saint Martin','MF');"
		sql+="insert into country(country_name,country_code)values('Saint Pierre and Miquelon','PM');"
		sql+="insert into country(country_name,country_code)values('Saint Vincent and the Grenadines','VC');"
		sql+="insert into country(country_name,country_code)values('Samoa','WS');"
		sql+="insert into country(country_name,country_code)values('San Marino','SM');"
		sql+="insert into country(country_name,country_code)values('Sao Tome and Principe','ST');"
		sql+="insert into country(country_name,country_code)values('Saudi Arabia','SA');"
		sql+="insert into country(country_name,country_code)values('Senegal','SN');"
		sql+="insert into country(country_name,country_code)values('Serbia','RS');"
		sql+="insert into country(country_name,country_code)values('Seychelles','SC');"
		sql+="insert into country(country_name,country_code)values('Sierra Leone','SL');"
		sql+="insert into country(country_name,country_code)values('Singapore','SG');"
		sql+="insert into country(country_name,country_code)values('Sint Maarten','SX');"
		sql+="insert into country(country_name,country_code)values('Slovakia','SK');"
		sql+="insert into country(country_name,country_code)values('Slovenia','SI');"
		sql+="insert into country(country_name,country_code)values('Solomon Islands','SB');"
		sql+="insert into country(country_name,country_code)values('Somalia','SO');"
		sql+="insert into country(country_name,country_code)values('South Africa','ZA');"
		sql+="insert into country(country_name,country_code)values('South Georgia and the South Sandwich Islands','GS');"
		sql+="insert into country(country_name,country_code)values('South Sudan','SS');"
		sql+="insert into country(country_name,country_code)values('Spain','ES');"
		sql+="insert into country(country_name,country_code)values('Sri Lanka','LK');"
		sql+="insert into country(country_name,country_code)values('Sudan','SD');"
		sql+="insert into country(country_name,country_code)values('Suriname','SR');"
		sql+="insert into country(country_name,country_code)values('Jan Mayen','SJ');"
		sql+="insert into country(country_name,country_code)values('Sweden','SE');"
		sql+="insert into country(country_name,country_code)values('Switzerland','CH');"
		sql+="insert into country(country_name,country_code)values('Syria','SY');"
		sql+="insert into country(country_name,country_code)values('Taiwan','TW');"
		sql+="insert into country(country_name,country_code)values('Tajikistan','TJ');"
		sql+="insert into country(country_name,country_code)values('Tanzania','TZ');"
		sql+="insert into country(country_name,country_code)values('Thailand','TH');"
		sql+="insert into country(country_name,country_code)values('East Timor','TL');"
		sql+="insert into country(country_name,country_code)values('Togo','TG');"
		sql+="insert into country(country_name,country_code)values('Tokelau','TK');"
		sql+="insert into country(country_name,country_code)values('Tonga','TO');"
		sql+="insert into country(country_name,country_code)values('Trinidad and Tobago','TT');"
		sql+="insert into country(country_name,country_code)values('Tunisia','TN');"
		sql+="insert into country(country_name,country_code)values('Turkey','TR');"
		sql+="insert into country(country_name,country_code)values('Turkmenistan','TM');"
		sql+="insert into country(country_name,country_code)values('Turks and Caicos Islands','TC');"
		sql+="insert into country(country_name,country_code)values('Tuvalu','TV');"
		sql+="insert into country(country_name,country_code)values('Uganda','UG');"
		sql+="insert into country(country_name,country_code)values('Ukraine','UA');"
		sql+="insert into country(country_name,country_code)values('United Arab Emirates','AE');"
		sql+="insert into country(country_name,country_code)values('United Kingdom','GB');"
		sql+="insert into country(country_name,country_code)values('United States Minor Outlying Islands','UM');"
		sql+="insert into country(country_name,country_code)values('United States of America','US');"
		sql+="insert into country(country_name,country_code)values('Uruguay','UY');"
		sql+="insert into country(country_name,country_code)values('Uzbekistan','UZ');"
		sql+="insert into country(country_name,country_code)values('Vanuatu','VU');"
		sql+="insert into country(country_name,country_code)values('Venezuela','VE');"
		sql+="insert into country(country_name,country_code)values('Vietnam','VN');"
		sql+="insert into country(country_name,country_code)values('British Virgin Islands','VG');"
		sql+="insert into country(country_name,country_code)values('United States Virgin Islands','VI');"
		sql+="insert into country(country_name,country_code)values('Wallis and Futuna','WF');"
		sql+="insert into country(country_name,country_code)values('Western Sahara','EH');"
		sql+="insert into country(country_name,country_code)values('Yemen','YE');"
		sql+="insert into country(country_name,country_code)values('Zambia','ZM');"
		sql+="insert into country(country_name,country_code)values('Zimbabwe','ZW');"
		sql+="insert into country(country_name,country_code)values('Unknown','??');"
		execute_sql "$sql"
		if (( $? != 0 ));then
			echo "[$$] Cannot initialise sqlite database at $DATABASE_FILE exiting..." >&2
			exit 4
		fi
	fi
}

# Make sure the version is at the latest version and upgrade the schema if possible.
check_and_upgrade_database(){

	db_version=$(execute_sql "select version from db_version;")
	if (( db_version != DATABASE_VERSION ));then
		echo "[$$] The database version is $db_version was expecting $DATABASE_VERSION" >&2
		exit 5;
	fi
	# Recover from a crash or abrupt finish.
	execute_sql "update DASH_NODES set check_in_progress_YN='N';"
	count=$(execute_sql "select count(1) from DASH_NODES;")
	echo "[$$] Database is up to date and contains a record of $count node(s)." >&2
	if [[ -z $IP ]] && (( count == 0 ));then
		echo "[$$] You must provide an IP and Port to start the scanning." >&2
		exit 7
	fi
}






# This function takes two arguments, and IP and a port number, it will then send the payload to the node via netcat
# Spin lock until enough data is gathered, kill the netcat process and then parse the data and update the database.
probe_node_and_parse_data(){

	if (( $# != 2 ));then echo "[$$] probe_node_and_parse_data requires exactly two argument." >&2;exit 11 ;fi
	dump_file="$DATADIR/dumps/$(date +"%Y%m%d%H%M%S")_$1_$2.bin"
	cat "$DATADIR"/payloads/payload_0[1234].bin | nc -v -w 120 "$1" "$2" > "$dump_file" &
	nc_pid=$!
	# If after 5 seconds the file size is still zero the host is dead.
	sleep 5
	if (( $(stat -c "%s" "$dump_file") == 0 ));then
		kill $nc_pid
		# Let's update the database there are two options.
		# 1) The node is new, insert it as such.
		# 2) It is an existing node that is no longer reachable, so update it.
		sql="select count(1) from DASH_NODES where ip=\"$1\" and port=$2;"
		count=$(execute_sql "$sql")
		if (( count>0 ));then
			sql="update DASH_NODES set active_ynu='N', checked_time=strftime('%s','now') where ip=\"$1\" and port=$2;"
			execute_sql "$sql"
		else
			sql="insert into DASH_NODES(ip, port, active_ynu, checked_time)values(\"$1\", $2, 'N', strftime('%s','now'));"
			execute_sql "$sql"
		fi
		return
	fi
	seconds=5

	while [[ $(pidof nc) =~ $nc_pid ]];do
		echo "[$$] $dump_file after $seconds sec has file size: $(stat -c "%s" "$dump_file")" >&2
		((seconds++))
		# Once the file size has reached a certain size we can assume we've got what we came for and don't need to wait any longer.
		# However don't kill it too soon in case the data is still streaming into the file.
		if (( $(stat -c "%s" "$dump_file") > 15000 ));then
			sleep 5
			kill $nc_pid
			echo "[$$] $dump_file after $((seconds+5)) sec has final file size: $(stat -c "%s" "$dump_file")" >&2
		fi
		sleep 1
	done

	# Now the nodes have been interrogated, time to parse the data files 
	# We will transpose the raw data into a hex string and find replys
	# of interest, eg version and addr and update the database.
	# These nodes were connectible, so update their proto version and user-agent.
	# Also, parse the addr response and add new nodes to the database where they don't already exist.
	# insert into DASH_NODES(ip,port,active_ynu,checked_time)values("1.2.3.4",45,'Y',strftime('%s','now'));
	# update DASH_NODES set checked_time=strftime('%s','now') where ip="1.2.3.4" and port=45;
	# select 1 from DASH_NODES where ip=$ip and port=$port; // Avoid an insert of a new IP if already found.
	# For a version command

	# This will change depending on which network is set.
	eval magic='$'"$NETWORK"_magic

	# The dump files don't have a final newline which causes read to skip it, so append one now.
	{ hexdump -v -e '/1 "%02X"' "$dump_file"|sed "s/\($magic\)/\n\1/g"|sed '/^$/d';echo; }|
	while IFS= read -r line;do
		# Match on the first 16 bytes which is the network magic and the command.
		case "$line" in
			# Version.
			"$magic"76657273696F6E0000000000*)
				echo "[$$] Got Version!" >&2
				# Verify the byte count.
				# The message header has length at by 17, arrays are indexed from zero, so 16, but in HEX, 2 chars = 1 byte
				# so double the offset and then read two bytes, wrap that with a base conversion gives us the size of the payload.
				# The line is twice the number of bytes stored, so divide by 2 to get the number of bytes the string represents.
				# The message header is 24 bytes long, so subtract that to get the size of the payload.
				if [[ $((16#${line:32:2})) != $((${#line} / 2 - 24)) ]];then
					echo "[$$] Data length mismatch for version message, skipping!" >&2
					break
				fi
				# Stored as little endian
				protocol_version="$((16#${line:54:2}${line:52:2}${line:50:2}${line:48:2}))"
				ua_length="$((16#${line:208:2}))"
				user_agent=$(xxd -r -p <<< "${line:210:$((ua_length * 2))}")
				# Not a serious error, but possible reasons for it to happen is if the string has a null byte or maybe ' or " then it could get truncated.
				if (( ua_length != ${#user_agent} ));then
					echo "[$$] The User Agent string \'$user_agent\' is ${#user_agent} characters long, but the reported length is $ua_length." >&2
				fi
				height="$((16#${line:$((ua_length * 2 + 6 + 210)):2}${line:$((ua_length * 2 + 4 + 210)):2}${line:$((ua_length * 2 + 2 + 210)):2}${line:$((ua_length * 2 + 0 + 210)):2}))"
				# Masternodes will have a larger payload than non-masternodes thanks to send 32 bytes of MNAUTH.
				echo "[$$] 120 + ua_length = $((120 + ua_length)) > $((16#${line:32:2}))" >&2
				if (( $((120 + ua_length)) > $((16#${line:32:2})) ));then
					masternode='Y'
				else
					masternode='N'
				fi

				# Store it in the database
				sql="select count(1) from DASH_NODES where ip=\"$1\" and port=$2;"
				count=$(execute_sql "$sql")
				if (( count>0 ));then
					# BUG: If the user-agent ends up having a " in the string it will cause these SQL statements to break.
					sql="update DASH_NODES set active_ynu='Y', last_active_time=strftime('%s','now'), last_seen_time=strftime('%s','now'), checked_time=strftime('%s','now'), protocol_version=$protocol_version, height=$height, user_agent=\"$user_agent\", masternode_ynu=\"$masternode\" where ip=\"$1\" and port=$2;"
					execute_sql "$sql"
				else
					sql="insert into DASH_NODES (ip, port, active_ynu, last_active_time, last_seen_time, checked_time, protocol_version, height, user_agent, masternode_ynu)values(\"$1\", $2, 'Y', strftime('%s','now'), strftime('%s','now'), strftime('%s','now'), $protocol_version, $height, \"$user_agent\",\"$masternode\");"
					execute_sql "$sql"
				fi
				;;
			# Addresses
			"$magic"616464720000000000000000*)
				echo "[$$] Got Addresses!" >&2
				# Verify the byte count.  It is bytes in little endian in position 17-20 so, 16-19 times 2
				if [[ $((16#${line:38:2}${line:36:2}${line:34:2}${line:32:2})) != $((${#line} / 2 - 24)) ]];then
					echo "[$$] Data length mismatch for address message, skipping!" >&2
					continue
				fi
				# Short messages are just echoing back the ip of the machine we have just connected to.
				(( $((16#${line:38:2}${line:36:2}${line:34:2}${line:32:2})) < 32 )) && continue
				# Non-dash nodes just pollute the database.
				if [[ ! $user_agent =~ "Dash Core" ]];then
					echo "[$$] Skipping node with user agent $user_agent." >&2
					continue
				fi
				num_ip="$((16#${line:52:2}${line:50:2}))"
				echo "[$$] This node $1:$2 sent $num_ip IPs to check." >&2
				echo "[$$] Inserting discovered IPs into the database..." >&2
				for((i=0; i<num_ip; i++));do
					if [[ "${line:$((78 + i * 60)):24}" = "00000000000000000000FFFF" ]];then
						ip="$((16#${line:$((102 + i * 60)):2})).$((16#${line:$((104 + i * 60)):2})).$((16#${line:$((106 + i * 60)):2})).$((16#${line:$((108 + i * 60)):2}))"
						port="$((16#${line:$((110 + i * 60)):4}))"
						# Insert into a temporary table for insert and duplicate processing in bulk in the database for much better performance.
						sql_insert+="insert into SEEN_NODES values(\"$ip\",$port);"
					else
						echo "[$$] Skipping IPv6 address..." >&2
					fi
				done
				# Run the sql and all the DB to do all the work assuming we have at least 1 IP to process.
				if (( num_ip > 0 ));then
					echo "[$$] Making changes to the database..." >&2
					sql="begin transaction;
						create temporary table SEEN_NODES(ip text NOT NULL,port integer NOT NULL, primary key(ip,port));"
					sql+="$sql_insert"
					sql+="update DASH_NODES set last_seen_time=strftime('%s','now') where exists (select 1 from SEEN_NODES t where DASH_NODES.ip=t.ip and DASH_NODES.port=t.port);
							select 'Updated '||changes()||' existing records (duplicates) in the database...';
							insert into DASH_NODES (ip,port,last_seen_time) select t.ip,t.port,strftime('%s','now') from temp.SEEN_NODES t where not exists (select 1 from DASH_NODES d where d.ip=t.ip and d.port=t.port);
							select 'Inserted '||changes()||' new records into the database...';
							commit;"
					execute_sql "$sql"
				fi
				echo "[$$] Database changes are complete." >&2
				;;
			"$magic"*)
				# For debugging only print any other message types sent from this node that we are ignoring.
				# Use tr to remove the null byte otherwise bash complains.
				msg=$(xxd -r -p <<<  "${line:8:24}"|tr -d '\000')
				echo "[$$] Ignoring unhandled message: $msg." >&2
				;;
			*)
				# This handles the case where we get data back from the node, but it wasn't actually a dash node at all.
				echo "[$$] Got unrecognised data from this node $1:$2 ==> $line" >&2
				sql="update DASH_NODES set active_ynu='N', checked_time=strftime('%s','now') where ip=\"$1\" and port=$2;"
				execute_sql "$sql"
				;;
		esac
	done
}

# Re-entrant code, skip all the fuss, the caller already did that and get straight to business.
if [[ -n $CHILD ]];then
	probe_node_and_parse_data "$IP" "$PORT"
	retval=$?
	execute_sql "update DASH_NODES set check_in_progress_YN='N' where ip=\"$IP\" and port=$PORT;"
	echo "[$$] Child process will now die." >&2
	exit $retval
fi


# Main part of the program.
echo "[$$] Checking program dependencies..."
check_dependencies

# $DATADIR can get set by a commandline option.
echo "[$$] Checking datadir $DATADIR..."
make_datadir

echo "[$$] Generating payloads..."
create_payloads

echo "[$$] Initialising database..."
initialise_database

echo "[$$] Checking database..."
check_and_upgrade_database




# Special case.
# If a node is given on the command line add it to the database so the database has at least one seed to get going.
if [[ -n $IP ]];then
	sql="insert into DASH_NODES(ip,port)values(\"$IP\",$PORT);"
	execute_sql "$sql"
	if (( $? != 0 ));then
		echo -e "[$$] Error inserting specified address $IP:$PORT into the database.\n[$$] Check that it doesn't already exist and try another." >&2
		exit 10
	fi
fi

# Main Loop.
echo "[$$] Starting main loop..."
idle_cycle=0
while : ;do

	# Get list of nodes that need to be checked.
	# First, find all the new nodes that have never been connected to at all.
	# Next, check any nodes that haven't been updated in the user defined timeframe.
	echo "[$$] Probing and updating all new and out of date nodes..."
	time=$((EPOCHSECONDS - POLL_TIME))

	sql="select count(1) from DASH_NODES where active_ynu='U' or (active_ynu!='U' and checked_time<$time);"
	# Count the number of times we go through the loop and do nothing, finish after a set limit.
	row_count=$(execute_sql "$sql")
	if (( row_count == 0 ));then
		((idle_cycle++))
	else
		idle_cycle=0
	fi

	sql="select ip,port from DASH_NODES where active_ynu='U' and check_in_progress_YN='N'"
	sql+="union all "
	sql+="select ip,port from ("
	sql+="select ip,port,checked_time from DASH_NODES where active_ynu!='U' and checked_time<$time and check_in_progress_YN='N' order by checked_time limit 500);"
	execute_sql "$sql"|
	while IFS='|' read -r IP PORT;do
		# We will mark the child as busy here before launching the process, the child will reverse this update just before exiting.
		execute_sql "update DASH_NODES set check_in_progress_YN='Y' where ip=\"$IP\" and port=$PORT;"
		echo "[$$] Checking $IP:$PORT..."
		# Make it re-entrant.
		"$0" -child -datadir "$DATADIR" -network "$NETWORK" "$IP" "$PORT" &

		# The hotspot in the code is the database access.
		# Check the error rate and slowdown if too fast.
		if ! ((EPOCHSECONDS%2));then
			while : ;do
				start_size=$(stat -c "%s" "$DATADIR"/logs/sqlite.log)
				sleep 2
				end_size=$(stat -c "%s" "$DATADIR"/logs/sqlite.log)
				((start_size==end_size))&&break
			done
		fi
	done
	sleep 5

	if (( idle_cycle > 30 ));then
		idle_cycle=0

		# Delete stale entries.
		time=$((EPOCHSECONDS - DELETE_TIME))
		sql="begin transaction;"
		sql+="delete from DASH_NODES where last_seen_time<$time;"
		sql+="select 'Deleted '||changes()||' stale records from the database...';commit;"
		execute_sql "$sql"
		execute_sql "vacuum;"

		# Adding in the location data.
		if [[ -f /usr/share/tor/geoip ]];then
			# We want to find all the missing country_codes and also any country_codes that have been recently updated.
			# An IP can feature in the data numerous times as several services can run from the same IP.
			sql="select distinct ip from dash_nodes where country_code is null;"
			ip_list=$(execute_sql "$sql")
			sql="begin transaction;"
			echo "[$$] Found $(wc -l <<< "$ip_list") IPs requiring country_code update..."
			while read ip junk;do
				ip_octet1=${ip%%\.*}
				ip_octet2=${ip#*\.};ip_octet2=${ip_octet2%%\.*}
				ip_octet3=${ip#*\.*\.};ip_octet3=${ip_octet3%%\.*}
				ip_octet4=${ip##*\.}
				x=$((ip_octet1*2**24 + ip_octet2*2**16 + ip_octet3*2**8 + ip_octet4))
				country_code="??"
				while IFS=',' read start end code junk;do
					[[ ${start:0:1} == "#" ]]&&continue
					((x>start && x<end))&&country_code="$code"&&break
				done < /usr/share/tor/geoip
				echo -n "."
				sql+="update dash_nodes set country_code='$country_code' where ip='$ip';"
			done <<< "$ip_list"
			sql+="commit;"
			execute_sql "$sql"
			echo -e "\n[$$] Done updating country_codes."
		fi
		echo "[$$] Making a backup of the database..."
		# This will be a good time to take a backup of the database.
		BACKUP_DB="$(dirname "$DATABASE_FILE")/$(date +"%Y%m%d%H%M%S")_nodes.db"
		cp "$DATABASE_FILE" "$BACKUP_DB"
		bzip2 -9 "$BACKUP_DB" >/dev/null 2>&1
		# Now place a copy over to the web folder
		cp "$DATABASE_FILE" /var/www/html/user-agents/.nodes.db
		# Now that the database is there update the user-agents page with the new data.
		~/bin/createUserAgents.sh >> ~/user-agents.log 2>&1
		str="[$$] The database is now fully updated, going to sleep for 30 minutes before\n"
		str+="[$$] updating again or you can exit now with CTRL + C and check the results."
		echo -e "$str"
		sleep 1800
	fi
done

