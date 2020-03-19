function getParameterByName(name) {
    name = name.replace(/[\[]/, "\\[").replace(/[\]]/, "\\]");
    var regex = new RegExp("[\\?&]" + name + "=([^&#]*)"),
        results = regex.exec(location.search);
    return results === null ? null : decodeURIComponent(results[1].replace(/\+/g, " "));
}

function getIP() {
    $.ajax({
        type: "GET",
        url: "https://api.ipify.org?format=json",
        success: function(data) {
            myIP = data.ip;
        }
    });
}

function PDCEFEvent(options) {
    var merged = $.extend(true, {}, {
            type: "POST",
            dataType: "json",
            headers: {
                "Accept": "application/vnd.pagerduty+json;version=2.0"
            },
            url: "https://events.pagerduty.com/v2/enqueue"

        },
        options);

    $.ajax(merged);
}

function PDRequest(token, endpoint, method, options) {

    if (!token) {
        return;
    }

    var merged = $.extend(true, {}, {
            type: method,
            dataType: "json",
            url: "https://api.pagerduty.com/" + endpoint,
            headers: {
                "Authorization": "Token token=" + token,
                "Accept": "application/vnd.pagerduty+json;version=2"
            },
            error: function(err, textStatus) {
                $('.busy').hide();
                var alertStr = "Error '" + err.status + " - " + err.statusText + "' while attempting " + method + " request to '" + endpoint + "'";
                try {
                    alertStr += ": " + err.responseJSON.error.message;
                } catch (e) {
                    alertStr += ".";
                }

                try {
                    alertStr += "\n\n" + err.responseJSON.error.errors.join("\n");
                } catch (e) {}

                alert(alertStr);
            }
        },
        options);

    $.ajax(merged);
}

function setPriority(incident_id, priority_id) {
    var options = {
        data: {
            "incident": {
            	"type": "incident_reference",
                "priority": {
                    "id": priority_id,
                    "type": "priority_reference"
                }
            }
        },
        headers: {
        	'From': getParameterByName('from_email')
        },
        success: function(data) {
        	console.log(data);
        }
    }
    PDRequest(getParameterByName('token'), `incidents/${incident_id}`, 'PUT', options);
}

function getPrioritiesAndSetPriority(incident_id) {
    var options = {
        success: function(data) {
            var priority = data['priorities'][0]['id'];
            setPriority(incident_id, priority);
        }
    };
    PDRequest(getParameterByName('token'), 'priorities', 'GET', options);
}

function findIncidentAndSetPriority(incident_key) {
    var options = {
        data: { 'incident_key': incident_key, 'statuses[]': 'triggered' },
        success: function(data) {
            console.log(data['incidents'][0]['id']);
            getPrioritiesAndSetPriority(data['incidents'][0]['id']);
        }
    }
    PDRequest(getParameterByName('token'), 'incidents', 'GET', options);
}

var myIP = "127.0.0.1";
var routing_key = getParameterByName('routing_key');
var count = 0;
var email = "unknown@example.com";

$('.alert').alert();

$('#inputEmail').keypress(function(e) {
    if (e.keyCode == 13) {
        $('#signin-button').trigger("click");
    }
});

$('#inputPassword').keypress(function(e) {
    if (e.keyCode == 13) {
        $('signin-button').trigger("click");
    }
});


$('#signin-button').on('click', function() {
    if (email != $('#inputEmail').val()) count = 0;
    count++;
    email = $('#inputEmail').val();

    var alertbox = `
	<div id="alert" class="alert alert-danger alert-dismissible fade show" role="alert">
		<button type="button" class="close" data-dismiss="alert" aria-label="Close">
			<span aria-hidden="true">&times;</span>
		</button>
		Invalid password for <strong>${email}</strong>. Please try again.
	</div>
	`;

    $('#alert-container').html(alertbox);

    var payload = {
        "event_action": "trigger",
        "client": "Splunk",
        "client_url": "http://54.193.12.191:8000/en-US/app/search/search?q=search%20login",
        "dedup_key": `failed_login_${email}`,
        "routing_key": routing_key,
        "payload": {
            "summary": `Attempted malicious logins for username ${email}`,
            "source": "Splunk",
            "severity": "critical",
            "custom_details": {
                "From": myIP,
                "Event": "Logon",
                "User": email,
                "Last_Attempt": new Date(),
                "To": document.title,
                "Failure_Times": count
            }
        }
    };

    var options = {
        data: JSON.stringify(payload)
    };

    PDCEFEvent(options)
});

$('#cu-signin-button').on('click', function() {
    if (email != $('#inputEmail').val()) count = 0;
    count++;
    email = $('#inputEmail').val();

    var alertbox = `
	<div id="alert" class="alert alert-danger alert-dismissible fade show" role="alert">
		<button type="button" class="close" data-dismiss="alert" aria-label="Close">
			<span aria-hidden="true">&times;</span>
		</button>
		Login failed for <strong>${email}</strong>. Please try again later.
	</div>
	`;

    $('#alert-container').html(alertbox);

    var payload = {
        "event_action": "trigger",
        "client": "Splunk",
        "client_url": "http://54.193.12.191:8000/en-US/app/search/search?q=search%20login",
        "dedup_key": `failed_login_${email}`,
        "routing_key": routing_key,
        "payload": {
            "summary": `Login failure for username ${email}`,
            "source": "Splunk",
            "severity": "critical",
            "custom_details": {
                "From": myIP,
                "Event": "Logon",
                "User": email,
                "Last_Attempt": new Date(),
                "To": document.title,
                "Failure_Times": count
            }
        }
    };

    var options = {
        data: JSON.stringify(payload),
        success: function(data) {
        	setTimeout(findIncidentAndSetPriority, 5000, `failed_login_${email}`);
            // findIncidentAndSetPriority(`failed_login_${email}`)
        }
    };

    PDCEFEvent(options)
});

getIP();
if (getParameterByName("title")) document.title = getParameterByName("title");