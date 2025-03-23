"""
IoT Security Monitoring Dashboard
===============================

Real-time dashboard for monitoring IoT network attacks.
"""

import logging
from datetime import datetime
import dash
from dash import html, dcc
from dash.dependencies import Input, Output
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
from pathlib import Path

from data.event_collector import EventCollector
from ml.attack_detector import AttackDetector

def setup_logging():
    """Configure logging for the monitoring system."""
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = log_dir / f"monitoring_{timestamp}.log"
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger("Monitoring")

# Initialize components
logger = setup_logging()
event_collector = EventCollector()
attack_detector = AttackDetector()

# Initialize Dash app
app = dash.Dash(__name__, title="IoT Security Monitor")

app.layout = html.Div([
    html.H1("IoT Security Monitoring Dashboard"),
    
    # Attack Statistics
    html.Div([
        html.H2("Attack Statistics"),
        dcc.Interval(id="stats-update", interval=5000),  # Update every 5 seconds
        html.Div(id="alert-stats")
    ]),
    
    # Charts Row
    html.Div([
        # Attack Timeline
        html.Div([
            html.H3("Attack Timeline"),
            dcc.Graph(id="attack-timeline")
        ], style={"width": "100%", "marginBottom": "20px"}),
        
        # Two columns for remaining charts
        html.Div([
            # Device Targeting
            html.Div([
                html.H3("Most Targeted Devices"),
                dcc.Graph(id="device-targeting")
            ], style={"width": "48%", "display": "inline-block"}),
            
            # Attack Success Rate
            html.Div([
                html.H3("Attack Success Rate"),
                dcc.Graph(id="attack-success")
            ], style={"width": "48%", "display": "inline-block", "float": "right"})
        ])
    ]),
    
    dcc.Interval(id="chart-update", interval=10000)  # Update charts every 10 seconds
])

@app.callback(
    Output("alert-stats", "children"),
    Input("stats-update", "n_intervals")
)
def update_stats(_):
    """Update alert statistics."""
    events = event_collector.get_events(event_type="security_alert", size=100)
    
    if not events:
        return html.Div([
            html.P("No alerts detected"),
            html.P("System Status: Active")
        ])
    
    # Calculate statistics
    total_alerts = len(events)
    recent_alerts = events[:5]
    
    # Count severity distribution
    severity_dist = {}
    for event in events:
        severity = event.get("severity", "unknown")
        severity_dist[severity] = severity_dist.get(severity, 0) + 1
    
    return html.Div([
        html.P(f"Total Alerts: {total_alerts}"),
        html.P(f"Severity Distribution: {severity_dist}"),
        html.H4("Recent Alerts:"),
        *[html.P(f"{alert['timestamp']}: {alert.get('details', {}).get('attack_type', 'Unknown')} "
                f"({alert.get('severity', 'unknown')})") 
          for alert in recent_alerts]
    ])

@app.callback(
    [Output("attack-timeline", "figure"),
     Output("device-targeting", "figure"),
     Output("attack-success", "figure")],
    Input("chart-update", "n_intervals")
)
def update_charts(_):
    """Update all chart visualizations."""
    events = event_collector.get_events(size=1000)
    if not events:
        return {}, {}, {}
    
    # Create DataFrame for easier analysis
    df = pd.DataFrame(events)
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    
    # 1. Attack Timeline
    timeline = go.Figure()
    timeline.add_trace(go.Scatter(
        x=df['timestamp'],
        y=df['alert_triggered'].astype(int),
        mode="lines",
        name="Attacks"
    ))
    timeline.update_layout(
        xaxis_title="Time",
        yaxis_title="Attack Detected",
        showlegend=True
    )
    
    # 2. Device Targeting
    target_counts = pd.Series([
        event.get('target', 'Unknown')
        for event in events
        if event.get('event_type') == 'security_alert'
    ]).value_counts()
    
    device_chart = px.bar(
        x=target_counts.index,
        y=target_counts.values,
        title="Attack Attempts by Target",
        labels={"x": "Device", "y": "Number of Attacks"}
    )
    
    # 3. Attack Success Rate
    success_counts = pd.Series([
        "Successful" if event.get('details', {}).get('success', False) else "Blocked"
        for event in events
        if event.get('event_type') == 'security_alert'
    ]).value_counts()
    
    success_chart = px.pie(
        values=success_counts.values,
        names=success_counts.index,
        title="Attack Success Rate"
    )
    
    return timeline, device_chart, success_chart

def main():
    """Run the monitoring dashboard."""
    try:
        logger.info("Starting IoT security monitoring system...")
        app.run_server(debug=True, port=8050)
        
    except Exception as e:
        logger.error(f"Monitoring failed: {str(e)}")
        raise

if __name__ == "__main__":
    main()