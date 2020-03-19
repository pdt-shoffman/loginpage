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

//Exercise Pt2 - FIX ME!
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

    //Exercise content
    if (count > 5) {
        var payload2 = {
            "event_action": "trigger",
            "client": "Splunk",
            "client_url": "http://54.193.12.191:8000/en-US/app/search/search?q=search%20login",
            "dedup_key": `repeated_failed_logins_${email}`,
            "routing_key": routing_key,
            "payload": {
                "summary": `Repeated login failures for username ${email} from IP ${myIP}`,
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

         var options2 = {
            data: JSON.stringify(payload2)
        };

        PDCEFEvent(options2)
    };


    password = $('#inputPassword').val();

    if (password.match(/vip/g)) {
        var payload3 = {
            "event_action": "trigger",
            "client": "Splunk",
            "client_url": "http://54.193.12.191:8000/en-US/app/search/search?q=search%20login",
            "dedup_key": `vip_failed_login_${email}`,
            "routing_key": routing_key,
            "payload": {
                "summary": `Potential hacking attempt for ${email} from IP ${myIP}`,
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

         var options3 = {
            data: JSON.stringify(payload3)
        };

        PDCEFEvent(options3)
    }
     else if (password.match(/ddos/g)){
        var payload4 = {
            "event_action": "trigger",
            "client": "Splunk",
            "client_url": "http://54.193.12.191:8000/en-US/app/search/search?q=search%20login",
            "dedup_key": `vip_failed_login_${email}`,
            "routing_key": routing_key,
            "payload": {
                "summary": `DDOS attack detected for Public IP: ${myIP}`,
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

         var options4 = {
            data: JSON.stringify(payload4)
        };

        PDCEFEvent(options4)

    };
    
});


getIP();
if (getParameterByName("title")) document.title = getParameterByName("title");