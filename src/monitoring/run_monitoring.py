"""
Attack Monitoring Dashboard
=========================

Real-time dashboard for monitoring IoT network attacks using Dash and Plotly.
"""

import logging
from datetime import datetime, timedelta
from pathlib import Path
import pandas as pd
from dash import Dash, html, dcc
from dash.dependencies import Input, Output
import plotly.express as px
import plotly.graph_objs as go

from data.event_collector import EventCollector

# Initialize logging
log_dir = Path("logs")
log_dir.mkdir(exist_ok=True)
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(log_dir / f"monitoring_{timestamp}.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("Monitoring")

# Initialize Dash app
app = Dash(__name__, title="IoT Security Monitor")
collector = EventCollector()

app.layout = html.Div([
    html.H1("IoT Security Monitoring Dashboard"),
    
    # Alert Statistics
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
    stats = collector.get_alert_stats()
    
    return html.Div([
        html.P(f"Total Alerts: {stats['total_alerts']}"),
        html.P(f"Recent Attack Types: {', '.join(stats['attack_types'].keys())}"),
        html.P(f"Severity Distribution: {stats['severity_distribution']}")
    ])

@app.callback(
    [Output("attack-timeline", "figure"),
     Output("device-targeting", "figure"),
     Output("attack-success", "figure")],
    Input("chart-update", "n_intervals")
)
def update_charts(_):
    """Update all charts with latest data."""
    # Get recent events
    events = collector.get_events(size=1000)
    if not events:
        return {}, {}, {}
        
    df = pd.DataFrame(events)
    
    # 1. Attack Timeline
    timeline = go.Figure()
    timeline.add_trace(go.Scatter(
        x=pd.to_datetime(df["timestamp"]),
        y=df["alert_triggered"].astype(int),
        mode="lines",
        name="Attacks"
    ))
    timeline.update_layout(
        xaxis_title="Time",
        yaxis_title="Attack Detected",
        showlegend=True
    )
    
    # 2. Device Targeting
    device_counts = pd.Series([
        d.get("target_device", {}).get("type", "Unknown")
        for d in df["details"]
    ]).value_counts()
    
    device_chart = px.bar(
        x=device_counts.index,
        y=device_counts.values,
        title="Attack Attempts by Device Type",
        labels={"x": "Device Type", "y": "Number of Attacks"}
    )
    
    # 3. Attack Success Rate
    success_counts = df["success"].value_counts()
    success_chart = px.pie(
        values=success_counts.values,
        names=success_counts.index,
        title="Attack Success Rate",
        labels={"success": "Successful", "failure": "Blocked"}
    )
    
    return timeline, device_chart, success_chart

def main():
    """Run the monitoring dashboard."""
    logger.info("Starting IoT Security Monitoring Dashboard")
    app.run_server(debug=True, port=8050)

if __name__ == "__main__":
    main()