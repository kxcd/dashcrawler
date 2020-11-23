#!/bin/bash
#set -x

VERSION="$0 (v0.2.2 build date 202011222010)"
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
		if [[ "$1" =~ ^[0-9]+$ ]];then
			echo -e "[$$] Protocol number be a number eg 70217." >&2
			exit 15
		fi
		PROTOCOL=$1
		shift
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

	perl -v >/dev/null 2>&1
	if (( $? != 0 ));then
		progs+=" perl"
	else
		perl -v|grep -q "This is perl " || echo "[$$] Please update your perl to at least version 5." >&2
	fi

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

# Takes 1 argument the hex string with no spaces, eg 'deadbeef01'
# and prints the raw data it represents.
hex_to_raw(){
	if (( $# != 1 ));then echo "[$$] hex_to_raw requires exactly one argument." >&2;exit 12 ;fi
	if [[ $1 =~ ^[a-f,A-F,0-9]+$ ]];then
		perl -pe 'y/A-Fa-f0-9//dc; $_= pack("H*",$_);' <<< "$1"
	else
		echo "[$$] Error converting $1 to raw." >&2
		exit 13
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
	payload_hash=$(hex_to_raw "$vers_payload"|sha256sum|while read -r a b;do h=$(hex_to_raw "$a"|sha256sum);echo "${h:0:8}";done)

	message_header=$net_magic_command$payload_size$payload_hash

	hex_to_raw "$message_header" >"$DATADIR"/payloads/payload_01.bin
	if (( $? != 0 ));then
		echo "[$$] Unable to create payload into $DATADIR/payloads/payload_01.bin exiting..." >&2
		exit 3
	fi
	hex_to_raw "$vers_payload" >"$DATADIR"/payloads/payload_02.bin

	# Just replay the next two payloads, nothing interesting or dynamic in them.
	hex_to_raw $net_magic"76657261636b000000000000000000005df6e0e2" >"$DATADIR"/payloads/payload_03.bin
	hex_to_raw $net_magic"676574616464720000000000000000005df6e0e2" >"$DATADIR"/payloads/payload_04.bin
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
		sql+="create table DASH_NODES(id INTEGER PRIMARY KEY ASC NOT NULL, ip TEXT NOT NULL, port INTEGER NOT NULL check(port>=0 and port<65536), active_YNU TEXT DEFAULT 'U' NOT NULL, last_active_time INTEGER,last_seen_time INTEGER, checked_time INTEGER, check_in_progress_YN TEXT DEFAULT 'N', protocol_version INTEGER, height INTEGER, user_agent TEXT, masternode_ynu TEXT DEFAULT 'U' NOT NULL);"
		sql+="create unique index idx_ip_port on DASH_NODES(ip,port);"
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
				user_agent=$(hex_to_raw "${line:210:$((ua_length * 2))}")
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
				msg=$(hex_to_raw  "${line:8:24}"|tr -d '\000')
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
		while : ;do
			start_size=$(stat -c "%s" "$DATADIR"/logs/sqlite.log)
			sleep 1
			end_size=$(stat -c "%s" "$DATADIR"/logs/sqlite.log)
			(( start_size==end_size))&&break
		done
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
		echo "[$$] Making a backup of the database..."
		# This will be a good time to take a backup of the database.
		BACKUP_DB="$(dirname "$DATABASE_FILE")/$(date +"%Y%m%d%H%M%S")_nodes.db"
		cp "$DATABASE_FILE" "$BACKUP_DB"
		bzip2 -9 "$BACKUP_DB" >/dev/null 2>&1
		str="[$$] The database is now fully updated, going to sleep for 30 minutes before\n"
		str+="[$$] updating again or you can exit now with CTRL + C and check the results."
		echo -e "$str"
		sleep 1800
	fi
done

