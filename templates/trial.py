import socket
import urllib.request
import requests

def check_wifi_connection():
    try:
        urllib.request.urlopen("https://www.google.com")
        return True
    except urllib.error.URLError:
        return False

def check_ethernet_connection():
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(("www.google.com", 80))
        return True
    except socket.error:
        return False

wifi_connected = check_wifi_connection()
ethernet_connected = check_ethernet_connection()

if wifi_connected:
    wifi_status = "Connected"
    wifi_strength = "5G"  # Replace with actual WiFi strength
    wifi_type = "5G"  # Replace with actual WiFi type (e.g. 5G, 4G, 3G)
else:
    wifi_status = "Not Connected"
    wifi_strength = ""
    wifi_type = ""

if ethernet_connected:
    ethernet_status = "Connected"
    ethernet_port = "Port 1"  # Replace with actual Ethernet port number
else:
    ethernet_status = "Not Connected"
    ethernet_port = ""

# Render the HTML template with the connection status
html_template = """
{% extends "base.html" %}
{% block title %}Firewall Status{% endblock %}
{% block content %}
<header>
    <div class="header">
        <div class="company-logo">
            <img src="/path/to/company-logo.png" alt="Company Logo">
        </div>

        <div class="connection-status">
            <span class="wifi-status">
                <i class="fas fa-wifi" style="color: {{ wifi_color }};"></i>
                <span class="wifi-dot {{ wifi_dot_class }}"></span>
                <span class="wifi-strength">{{ wifi_strength }} ({{ wifi_type }})</span>
            </span>

            <span class="ethernet-status">
                <i class="fas fa-network-wired" style="color: {{ ethernet_color }};"></i>
                <span class="ethernet-dot {{ ethernet_dot_class }}"></span>
                <span class="ethernet-port">{{ ethernet_port }}</span>
            </span>
        </div>

        <a href="/logout" class="btn btn-outline-danger">Logout</a>
    </div>
</header>

{% include "navbar.html" %}

<div class="container mt-5">
    <div id="plot"></div>
</div>

<script>
    var data = [];
    var diffs = [];
    var layout = { 
        title: 'Firewall' , 
        xaxis: { type: 'date', tickformat: '%H:%M:%S' } ,
        transition: { duration: 500, easing: 'cubic-in-out' }
    };
    var config = { responsive: true };

    var plotDiv = document.getElementById('plot');
    var plot = Plotly.newPlot(plotDiv, [{ y: data }], layout, config);

    var eventSource = new EventSource('/firewall_traffic');
    eventSource.onmessage = function (event) {
        data.push(parseInt(event.data));
        if(data.length >= 2){
            let diff = Math.abs([data.length-1] - data[data.length-2]);
            console.log(diff);
            diffs.push(diff);
            Plotly.update(plotDiv, { y: [diffs] ,type: 'scatter'});
        }
    };
</script>
{% endblock %}
"""

wifi_color = "green" if wifi_connected else "red"
ethernet_color = "green" if ethernet_connected else "red"
wifi_dot_class = "connected" if wifi_connected else "disconnected"
ethernet_dot_class = "connected" if ethernet_connected else "disconnected"

rendered_html = html_template.replace("{{ wifi_color }}", wifi_color)
rendered_html = rendered_html.replace("{{ ethernet_color }}", ethernet_color)
rendered_html = rendered_html.replace("{{ wifi_dot_class }}", wifi_dot_class)
rendered_html = rendered_html.replace("{{ ethernet_dot_class }}", ethernet_dot_class)
rendered_html = rendered_html.replace("{{ wifi_strength }}", wifi_strength)
rendered_html = rendered_html.replace("{{ wifi_type }}", wifi_type)
rendered_html = rendered_html.replace("{{ ethernet_port }}", ethernet_port)

print(rendered_html)