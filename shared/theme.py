# Shared design token layer across Tessera, VerityFlux, and Vestigia.

COLORS = {
    # foundation — ARTO dark "ink" (locked brand)
    "bg_primary": "#0B0E16",      # app background
    "bg_secondary": "#121725",    # panels / cards
    "bg_tertiary": "#090C13",     # code blocks / deepest
    "sidebar": "#090C13",
    "sidebar_panel": "#121725",
    "rule": "#2A3344",            # border
    "dark_rule": "#1E2635",       # border-soft
    "white": "#FFFFFF",           # on-accent text
    "text": "#E7EAF3",
    "light_blue": "#B5ACFF",      # acc-200 tint (sidebar text / code)
    "muted": "#9AA3B8",
    "terminal_muted": "#6B7488",
    # severity — RESERVED for meaning, never the brand accent
    "teal": "#3FB98A",            # healthy / ok
    "red": "#F04852",             # critical
    "amber": "#F6913B",           # warning / high
    # brand accent — Electric Indigo (one accent across the whole suite)
    "accent": "#6E5CF7",
    "accent_hover": "#897AFF",
    "accent_soft": "rgba(110, 92, 247, 0.16)",
}

# One brand accent across all three tools — the suite reads as a single product.
TOOL_ACCENTS = {
    "tessera": COLORS["accent"],
    "verityflux": COLORS["accent"],
    "vestigia": COLORS["accent"],
}


def inject_css(tool: str = "suite"):
    import streamlit as st

    accent = TOOL_ACCENTS.get(tool.lower(), COLORS["teal"])
    st.markdown(f"""
<style>
@import url('https://fonts.googleapis.com/css2?family=Archivo:wght@600;700;800&family=IBM+Plex+Sans:wght@400;500;600&family=JetBrains+Mono:wght@400;500&display=swap');

.stApp, [data-testid="stAppViewContainer"], [data-testid="stMainBlockContainer"] {{
    background-color: {COLORS['bg_primary']} !important;
    color: {COLORS['text']} !important;
    font-family: 'IBM Plex Sans', system-ui, -apple-system, sans-serif !important;
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
    font-family: 'Archivo', 'IBM Plex Sans', system-ui, sans-serif !important;
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
    font-family: 'IBM Plex Sans', system-ui, sans-serif !important;
    font-size: 13px !important;
    font-weight: 500 !important;
    padding: 6px 14px !important;
}}

.stButton > button:hover {{
    filter: brightness(1.08) !important;
    border-color: {accent} !important;
}}

[data-testid="stHeader"] {{
    background: rgba(11, 14, 22, 0.92) !important;
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
