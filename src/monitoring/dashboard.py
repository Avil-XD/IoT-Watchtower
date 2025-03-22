import logging
from pathlib import Path
from datetime import datetime
import dash
from dash import html, dcc
import dash_bootstrap_components as dbc
from dash.dependencies import Input, Output
import plotly.graph_objs as go
import pandas as pd

class MonitoringDashboard:
    def __init__(self):
        """Initialize the monitoring dashboard."""
        self._setup_logging()
        self.app = dash.Dash(
            __name__,
            external_stylesheets=[dbc.themes.BOOTSTRAP],
            assets_folder=str(Path(__file__).parent / "static")
        )
        self.setup_layout()
        self.detection_history = []
        self.network_metrics = []

    def _setup_logging(self):
        """Configure dashboard-specific logging."""
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = log_dir / f"dashboard_{timestamp}.log"
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger("Dashboard")

    def setup_layout(self):
        """Set up the dashboard layout."""
        self.app.layout = dbc.Container([
            dbc.Row([
                dbc.Col(html.H1("IoT Network Security Monitor", className="text-center mb-4"))
            ]),
            
            dbc.Row([
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader(html.H3("Network Status")),
                        dbc.CardBody([
                            dcc.Graph(id='network-status-graph'),
                            dcc.Interval(
                                id='network-status-update',
                                interval=5000
                            )
                        ])
                    ])
                ], width=6),
                
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader(html.H3("Attack Detection")),
                        dbc.CardBody([
                            dcc.Graph(id='attack-detection-graph'),
                            dcc.Interval(
                                id='attack-detection-update',
                                interval=5000
                            )
                        ])
                    ])
                ], width=6)
            ]),
            
            dbc.Row([
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader(html.H3("Recent Alerts")),
                        dbc.CardBody([
                            html.Div(id='alerts-table'),
                            dcc.Interval(
                                id='alerts-update',
                                interval=5000
                            )
                        ])
                    ])
                ], width=6),
                
                dbc.Col([
                    dbc.Card([
                        dbc.CardHeader(html.H3("Network Metrics")),
                        dbc.CardBody([
                            html.Div(id='metrics-table'),
                            dcc.Interval(
                                id='metrics-update',
                                interval=5000
                            )
                        ])
                    ])
                ], width=6)
            ], className="mt-4")
        ], fluid=True)

        self._setup_callbacks()

    def _setup_callbacks(self):
        """Set up dashboard update callbacks."""
        @self.app.callback(
            Output('network-status-graph', 'figure'),
            [Input('network-status-update', 'n_intervals')]
        )
        def update_network_status(n):
            return self._create_network_status_figure()

        @self.app.callback(
            Output('attack-detection-graph', 'figure'),
            [Input('attack-detection-update', 'n_intervals')]
        )
        def update_attack_detection(n):
            return self._create_attack_detection_figure()

        @self.app.callback(
            Output('alerts-table', 'children'),
            [Input('alerts-update', 'n_intervals')]
        )
        def update_alerts(n):
            return self._create_alerts_table()

        @self.app.callback(
            Output('metrics-table', 'children'),
            [Input('metrics-update', 'n_intervals')]
        )
        def update_metrics(n):
            return self._create_metrics_table()

    def _create_network_status_figure(self):
        """Create network status visualization."""
        if not self.network_metrics:
            return go.Figure()

        df = pd.DataFrame(self.network_metrics[-50:])
        
        fig = go.Figure()
        fig.add_trace(go.Scatter(
            x=df['timestamp'],
            y=df['bandwidth_usage'],
            name='Bandwidth Usage',
            line=dict(color='blue')
        ))
        fig.add_trace(go.Scatter(
            x=df['timestamp'],
            y=df['error_rate'],
            name='Error Rate',
            line=dict(color='red')
        ))
        
        fig.update_layout(
            title='Network Performance',
            xaxis_title='Time',
            yaxis_title='Value',
            height=400,
            margin=dict(l=40, r=40, t=40, b=40)
        )
        
        return fig

    def _create_attack_detection_figure(self):
        """Create attack detection visualization."""
        if not self.detection_history:
            return go.Figure()

        df = pd.DataFrame(self.detection_history[-50:])
        
        fig = go.Figure()
        for attack_type in df['detected_type'].unique():
            mask = df['detected_type'] == attack_type
            fig.add_trace(go.Scatter(
                x=df[mask]['timestamp'],
                y=df[mask]['confidence'],
                name=attack_type,
                mode='lines+markers'
            ))
        
        fig.update_layout(
            title='Attack Detection Confidence',
            xaxis_title='Time',
            yaxis_title='Confidence',
            height=400,
            margin=dict(l=40, r=40, t=40, b=40)
        )
        
        return fig

    def _create_alerts_table(self):
        """Create alerts table."""
        alerts = [
            alert for alert in self.detection_history[-10:]
            if alert['alert_triggered']
        ]
        
        if not alerts:
            return html.P("No recent alerts")
        
        return dbc.Table([
            html.Thead(html.Tr([
                html.Th("Time"),
                html.Th("Type"),
                html.Th("Confidence")
            ])),
            html.Tbody([
                html.Tr([
                    html.Td(alert['timestamp'].strftime("%H:%M:%S")),
                    html.Td(alert['detected_type']),
                    html.Td(f"{alert['confidence']:.3f}")
                ], className=f"table-{'danger' if alert['is_attack'] else 'warning'}")
                for alert in alerts
            ])
        ], bordered=True, hover=True, striped=True)

    def _create_metrics_table(self):
        """Create metrics table."""
        if not self.network_metrics:
            return html.P("No metrics available")
        
        latest = self.network_metrics[-1]
        
        return dbc.Table([
            html.Thead(html.Tr([
                html.Th("Metric"),
                html.Th("Value")
            ])),
            html.Tbody([
                html.Tr([
                    html.Td(k.replace('_', ' ').title()),
                    html.Td(f"{v:.3f}")
                ])
                for k, v in latest.items()
                if k != 'timestamp'
            ])
        ], bordered=True, hover=True)

    def update_data(self, network_status, detection_result):
        """Update dashboard data."""
        timestamp = datetime.now()
        
        # Update network metrics
        self.network_metrics.append({
            'timestamp': timestamp,
            'bandwidth_usage': network_status['metrics']['total_bandwidth'],
            'error_rate': network_status['metrics']['error_rate'],
            'packet_loss': network_status['metrics']['packet_loss_rate'],
            'latency': network_status['metrics']['latency']
        })
        
        # Update detection history
        detection_result['timestamp'] = timestamp
        self.detection_history.append(detection_result)
        
        # Trim old data
        max_history = 1000
        if len(self.network_metrics) > max_history:
            self.network_metrics = self.network_metrics[-max_history:]
        if len(self.detection_history) > max_history:
            self.detection_history = self.detection_history[-max_history:]

    def run(self, host='localhost', port=8050, debug=False):
        """Run the dashboard server."""
        self.logger.info(f"Starting dashboard server on {host}:{port}")
        self.app.run_server(host=host, port=port, debug=debug)