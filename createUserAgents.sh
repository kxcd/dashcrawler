#!/bin/bash
#set -x
set -e


PATH=$PATH:/opt/dash/bin
dcli(){
	dash-cli -datadir=/tmp -conf=/etc/dash.conf "$@"
}


# Stream to this file.
f="/var/www/html/user-agents/.index.html"

# Publish to this file.
ff="/var/www/html/user-agents/index.html"

database_file="/var/www/html/user-agents/.nodes.db"


# Checks that the required software is installed on this machine.
check_dependencies(){
	unset progs
	jq --help >/dev/null 2>&1 || progs+=" jq"
	sqlite3 -version >/dev/null 2>&1 || progs+=" sqlite3"

	if [[ -n $progs ]];then
		msg="[$$] $VERSION\n[$$] Missing applications on your system, please run\n\n"
		msg+="[$$] sudo apt install $progs\n\n[$$] before running this program again."
		echo -e "$msg" >&2
		exit 1
	fi
}
check_dependencies





cat >"$f"<<"EOF"
<!DOCTYPE html>
<html lang="en">
	<head>
		<meta charset="utf-8">
		<meta name="description" content="Dash P2P network user agents">
		<link rel="icon" type="image/png" href="/favicon.ico"/>
		<link rel="stylesheet" type="text/css" href="useragents.css"/>
		<script src="https://www.gstatic.com/charts/loader.js"></script>
		<title>DASH User Agents</title>
	</head>
<body>
<h1>DASH User Agents</h1>
<div id="all" class="pie"></div>
<script>
google.charts.load('current', {'packages':['corechart']});
google.charts.setOnLoadCallback(drawChart);

function drawChart() {
  var data = google.visualization.arrayToDataTable([
  ['User-Agent', 'Count'],
EOF

# Need to create the data structure from the query.
sql="select '  ['''||user_agent||''',' ||cnt||'],' from (select user_agent,count(1)as cnt from DASH_NODES group by user_agent order by 2 desc);"
res=$(sqlite3 "$database_file"<<<"$sql")
res="${res:0:((${#res}-1))}"
echo "$res"|sed 's|/||'>>"$f"




cat >>"$f"<<"EOF"
]);

  var options = {title:'All User Agents',backgroundColor:'black',titleTextStyle:{color:'white'},legend:{textStyle:{color:'white'}},sliceVisibilityThreshold:.0001,is3D:true};

  // Display the chart inside the <div> element with id="all"
  var chart = new google.visualization.PieChart(document.getElementById('all'));
  chart.draw(data, options);
}
</script>
EOF








cat >>"$f"<<"EOF"
<div id="dash-only" class="pie"></div>
<script>
google.charts.load('current', {'packages':['corechart']});
google.charts.setOnLoadCallback(drawChart);

function drawChart() {
  var data = google.visualization.arrayToDataTable([
  ['User-Agent', 'Count'],
EOF


sql="select '  ['''||user_agent||''',' ||cnt||'],' from (select user_agent,count(1)as cnt from DASH_NODES where user_agent like '%Dash Core%' group by user_agent order by 2 desc);"
res=$(sqlite3 "$database_file"<<<"$sql")
res="${res:0:((${#res}-1))}"
echo "$res"|sed 's|/||'>>"$f"



cat >>"$f"<<"EOF"
]);

  var options = {title:'DASH Only User Agents',backgroundColor:'black',titleTextStyle:{color:'white'},legend:{textStyle:{color:'white'}},sliceVisibilityThreshold:.0001,is3D:true};

  var chart = new google.visualization.PieChart(document.getElementById('dash-only'));
  chart.draw(data, options);
}
</script>
EOF







cat >>"$f"<<"EOF"
<div id="dash-only-location" class="pie"></div>
<script>
google.charts.load('current', {'packages':['corechart']});
google.charts.setOnLoadCallback(drawChart);

function drawChart() {
  var data = google.visualization.arrayToDataTable([
  ['Country', 'Count'],
EOF


sql="select '  ['''||country_name||''',' ||cnt||'],' from (select country_name,count(1)as cnt from DASH_NODES d join country c on c.country_code=d.country_code where user_agent like '%Dash Core%' group by country_name order by 2 desc);"
res=$(sqlite3 "$database_file"<<<"$sql")
res="${res:0:((${#res}-1))}"
echo "$res"|sed 's|/||'>>"$f"



cat >>"$f"<<"EOF"
]);

  var options = {title:'DASH Only Full Nodes by Country',backgroundColor:'black',titleTextStyle:{color:'white'},legend:{textStyle:{color:'white'}},sliceVisibilityThreshold:.0001,is3D:true};

  var chart = new google.visualization.PieChart(document.getElementById('dash-only-location'));
  chart.draw(data, options);
}
</script>
EOF







cat >>"$f"<<"EOF"
<div id="protocol-dash-only" class="pie"></div>
<script>
google.charts.load('current', {'packages':['corechart']});
google.charts.setOnLoadCallback(drawChart);

function drawChart() {
  var data = google.visualization.arrayToDataTable([
  ['Protocol', 'Count'],
EOF



sql="select '  ['''||protocol_version||''',' ||cnt||'],' from (select protocol_version,count(1)as cnt from DASH_NODES where user_agent like '%Dash Core%' group by protocol_version order by 2 desc);"
res=$(sqlite3 "$database_file"<<<"$sql")
res="${res:0:((${#res}-1))}"
echo "$res"|sed 's|/||'>>"$f"



cat >>"$f"<<"EOF"
]);

  var options = {title:'DASH Only Protocol Versions',backgroundColor:'black',titleTextStyle:{color:'white'},legend:{textStyle:{color:'white'}},sliceVisibilityThreshold:.0001,is3D:true};

  var chart = new google.visualization.PieChart(document.getElementById('protocol-dash-only'));
  chart.draw(data, options);
}
</script>
EOF













cat >>"$f"<<"EOF"
<div id="reachable-dash-only" class="pie"></div>
<script>
google.charts.load('current', {'packages':['corechart']});
google.charts.setOnLoadCallback(drawChart);

function drawChart() {
  var data = google.visualization.arrayToDataTable([
  ['Reachable', 'Count'],
EOF



sql="select '  ['''||reachable||''',' ||cnt||'],' from (select case active_ynu when 'Y' then 'Yes' when 'N' then 'No' else 'Unknown' end as reachable,count(1)as cnt from DASH_NODES where user_agent like '%Dash Core%' group by reachable order by 2 desc);"
res=$(sqlite3 "$database_file"<<<"$sql")
res="${res:0:((${#res}-1))}"
echo "$res"|sed 's|/||'>>"$f"



cat >>"$f"<<"EOF"
]);

  var options = {title:'DASH Only Reachable Nodes',backgroundColor:'black',titleTextStyle:{color:'white'},legend:{textStyle:{color:'white'}},sliceVisibilityThreshold:.0001,is3D:true};

  var chart = new google.visualization.PieChart(document.getElementById('reachable-dash-only'));
  chart.draw(data, options);
}
</script>
EOF










#  Now let's update the database with the current list of masternodes and report on the Masternode population only.

sql="begin transaction;update dash_nodes set masternode_ynu='N';"
sql+=$(dcli protx list valid 1|jq -r '.[].state.service'|sed "s/\(.*\):\(.*\)/update dash_nodes set masternode_ynu='Y' where ip='\1' and port=\2;/")
sql+="select count(1)from dash_nodes where masternode_ynu='Y';commit;"
res=$(sqlite3 "$database_file"<<<"$sql")

# I want to skip the Masternode charts if some reason the updates failed.
if ((res>3000));then





cat >>"$f"<<"EOF"
<div id="dash-only-mn" class="pie"></div>
<script>
google.charts.load('current', {'packages':['corechart']});
google.charts.setOnLoadCallback(drawChart);

function drawChart() {
  var data = google.visualization.arrayToDataTable([
  ['User-Agent', 'Count'],
EOF


sql="select '  ['''||user_agent||''',' ||cnt||'],' from (select user_agent,count(1)as cnt from DASH_NODES where masternode_ynu='Y' group by user_agent order by 2 desc);"
res=$(sqlite3 "$database_file"<<<"$sql")
res="${res:0:((${#res}-1))}"
echo "$res"|sed 's|/||'>>"$f"



cat >>"$f"<<"EOF"
]);

  var options = {title:'DASH Masternode User Agents',backgroundColor:'black',titleTextStyle:{color:'white'},legend:{textStyle:{color:'white'}},sliceVisibilityThreshold:.0001,is3D:true};

  var chart = new google.visualization.PieChart(document.getElementById('dash-only-mn'));
  chart.draw(data, options);
}
</script>
EOF







cat >>"$f"<<"EOF"
<div id="dash-only-mn-location" class="pie"></div>
<script>
google.charts.load('current', {'packages':['corechart']});
google.charts.setOnLoadCallback(drawChart);

function drawChart() {
  var data = google.visualization.arrayToDataTable([
  ['Country', 'Count'],
EOF

sql="select '  ['''||country_name||''',' ||cnt||'],' from (select country_name,count(1)as cnt from DASH_NODES d join country c on c.country_code=d.country_code where masternode_ynu='Y' group by country_name order by 2 desc);"
res=$(sqlite3 "$database_file"<<<"$sql")
res="${res:0:((${#res}-1))}"
echo "$res"|sed 's|/||'>>"$f"



cat >>"$f"<<"EOF"
]);

  var options = {title:'DASH Masternodes by Country',backgroundColor:'black',titleTextStyle:{color:'white'},legend:{textStyle:{color:'white'}},sliceVisibilityThreshold:.0001,is3D:true};

  var chart = new google.visualization.PieChart(document.getElementById('dash-only-mn-location'));
  chart.draw(data, options);
}
</script>
EOF







cat >>"$f"<<"EOF"
<div id="protocol-dash-only-mn" class="pie"></div>
<script>
google.charts.load('current', {'packages':['corechart']});
google.charts.setOnLoadCallback(drawChart);

function drawChart() {
  var data = google.visualization.arrayToDataTable([
  ['Protocol', 'Count'],
EOF



sql="select '  ['''||protocol_version||''',' ||cnt||'],' from (select protocol_version,count(1)as cnt from DASH_NODES where masternode_ynu='Y' group by protocol_version order by 2 desc);"
res=$(sqlite3 "$database_file"<<<"$sql")
res="${res:0:((${#res}-1))}"
echo "$res"|sed 's|/||'>>"$f"



cat >>"$f"<<"EOF"
]);

  var options = {title:'DASH Masternode Protocol Versions',backgroundColor:'black',titleTextStyle:{color:'white'},legend:{textStyle:{color:'white'}},sliceVisibilityThreshold:.0001,is3D:true};

  var chart = new google.visualization.PieChart(document.getElementById('protocol-dash-only-mn'));
  chart.draw(data, options);
}
</script>
EOF






cat >>"$f"<<"EOF"
<div id="reachable-dash-only-mn" class="pie"></div>
<script>
google.charts.load('current', {'packages':['corechart']});
google.charts.setOnLoadCallback(drawChart);

function drawChart() {
  var data = google.visualization.arrayToDataTable([
  ['Reachable', 'Count'],
EOF



sql="select '  ['''||reachable||''',' ||cnt||'],' from (select case active_ynu when 'Y' then 'Yes' when 'N' then 'No' else 'Unknown' end as reachable,count(1)as cnt from DASH_NODES where masternode_ynu='Y' group by reachable order by 2 desc);"
res=$(sqlite3 "$database_file"<<<"$sql")
res="${res:0:((${#res}-1))}"
echo "$res"|sed 's|/||'>>"$f"



cat >>"$f"<<"EOF"
]);

  var options = {title:'DASH Masternode Reachable Nodes',backgroundColor:'black',titleTextStyle:{color:'white'},legend:{textStyle:{color:'white'}},sliceVisibilityThreshold:.0001,is3D:true};

  var chart = new google.visualization.PieChart(document.getElementById('reachable-dash-only-mn'));
  chart.draw(data, options);
}
</script>
EOF








fi

echo "<p>Generated at: $(date)</p>">>"$f"

cat >>"$f"<<"EOF"
</body>
</html>
EOF

# Now we are done with staging the file, so publish it.
mv "$f" "$ff"

