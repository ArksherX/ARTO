# Shared design token layer across Tessera, VerityFlux, and Vestigia.

COLORS = {
    "bg_primary": "#F5F7FA",
    "bg_secondary": "#FFFFFF",
    "bg_tertiary": "#0A1825",
    "sidebar": "#060D14",
    "sidebar_panel": "#0F2236",
    "rule": "#D8E0EA",
    "dark_rule": "#162840",
    "white": "#FFFFFF",
    "text": "#172033",
    "light_blue": "#A8C4DC",
    "muted": "#607086",
    "terminal_muted": "#3D5A73",
    "teal": "#0F6E56",
    "red": "#C0392B",
    "amber": "#E67E22",
}

TOOL_ACCENTS = {
    "tessera": COLORS["teal"],
    "verityflux": COLORS["red"],
    "vestigia": COLORS["light_blue"],
}


def inject_css(tool: str = "suite"):
    import streamlit as st

    accent = TOOL_ACCENTS.get(tool.lower(), COLORS["teal"])
    st.markdown(f"""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&family=JetBrains+Mono:wght@400;500&display=swap');

.stApp, [data-testid="stAppViewContainer"], [data-testid="stMainBlockContainer"] {{
    background-color: {COLORS['bg_primary']} !important;
    color: {COLORS['text']} !important;
    font-family: 'Inter', sans-serif !important;
}}

.block-container {{
    padding-top: 1.2rem !important;
    padding-left: 1.6rem !important;
    padding-right: 1.6rem !important;
    max-width: 100% !important;
}}

[data-testid="stSidebar"], [data-testid="stSidebarContent"] {{
    background-color: {COLORS['sidebar']} !important;
    border-right: 1px solid {COLORS['dark_rule']} !important;
}}

[data-testid="stSidebar"] * {{
    color: {COLORS['light_blue']} !important;
}}

h1, h2, h3, h4 {{
    font-family: 'Inter', sans-serif !important;
    font-weight: 600 !important;
    color: {COLORS['text']} !important;
    letter-spacing: 0 !important;
    border-bottom: 1px solid {COLORS['rule']} !important;
    padding-bottom: 6px !important;
    margin-top: 1rem !important;
}}

p, label, span, div {{
    letter-spacing: 0 !important;
}}

p, li, label, .stMarkdown, [data-testid="stCaptionContainer"] {{
    color: {COLORS['text']} !important;
}}

[data-testid="stMetricWidget"], div[data-element-to-marshal="metric"], .stMetric {{
    background-color: {COLORS['bg_secondary']} !important;
    border-left: 3px solid {accent} !important;
    border-top: 1px solid {COLORS['rule']} !important;
    border-right: 1px solid {COLORS['rule']} !important;
    border-bottom: 1px solid {COLORS['rule']} !important;
    padding: 12px 16px !important;
    border-radius: 4px !important;
    box-shadow: none !important;
}}

[data-testid="stMetricValue"] > div {{
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 30px !important;
    font-weight: 500 !important;
    color: {COLORS['text']} !important;
}}

[data-testid="stMetricLabel"] > div {{
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 11px !important;
    color: {COLORS['muted']} !important;
    text-transform: uppercase !important;
}}

code, pre, [data-testid="stCodeBlock"] {{
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 13px !important;
    background-color: {COLORS['bg_tertiary']} !important;
    color: {COLORS['light_blue']} !important;
    border: 1px solid {COLORS['dark_rule']} !important;
    border-radius: 2px !important;
}}

.stSelectbox div[data-baseweb="select"], .stTextInput input, .stTextArea textarea, .stMultiSelect div[data-baseweb="select"] {{
    background-color: {COLORS['bg_secondary']} !important;
    border: 1px solid {COLORS['rule']} !important;
    color: {COLORS['text']} !important;
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 13px !important;
    border-radius: 4px !important;
}}

.stButton > button {{
    background-color: {accent} !important;
    color: {COLORS['white']} !important;
    border: 1px solid {accent} !important;
    border-radius: 3px !important;
    font-family: 'Inter', sans-serif !important;
    font-size: 13px !important;
    font-weight: 500 !important;
    padding: 6px 14px !important;
}}

.stButton > button:hover {{
    filter: brightness(1.08) !important;
    border-color: {accent} !important;
}}

[data-testid="stHeader"] {{
    background: rgba(245, 247, 250, 0.92) !important;
    border-bottom: 1px solid {COLORS['rule']} !important;
}}

[data-testid="stBlock"] {{
    gap: 10px !important;
}}

[data-testid="stExpander"], [data-testid="stDataFrame"], div[data-testid="stAlert"] {{
    background-color: {COLORS['bg_secondary']} !important;
    border: 1px solid {COLORS['rule']} !important;
    border-radius: 4px !important;
    color: {COLORS['text']} !important;
}}

[data-testid="stRadio"] label, [data-testid="stCheckbox"] label, [data-testid="stSlider"] label {{
    color: {COLORS['text']} !important;
}}

.status-box {{
    background-color: {COLORS['bg_secondary']};
    border: 1px solid {COLORS['rule']};
    border-left: 4px solid {accent};
    border-radius: 3px;
    padding: 10px 12px;
    margin: 8px 0 12px 0;
    color: {COLORS['text']};
}}

.status-box.critical {{ border-left-color: {COLORS['red']}; }}
.status-box.warning {{ border-left-color: {COLORS['amber']}; }}
.status-box.healthy {{ border-left-color: {COLORS['teal']}; }}
.telemetry-time {{
    font-family: 'JetBrains Mono', monospace;
    font-size: 11px;
    color: {COLORS['terminal_muted']};
}}
</style>
""", unsafe_allow_html=True)


def status_box(message: str, severity: str = "healthy") -> str:
    severity = severity if severity in {"healthy", "warning", "critical"} else "healthy"
    return f'<div class="status-box {severity}">{message}</div>'
