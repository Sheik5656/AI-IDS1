import streamlit as st
import pandas as pd
import numpy as np
import plotly.graph_objects as go
import plotly.express as px
from datetime import datetime
import time
import sys
import os
import threading
import tempfile
import base64

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.packet_sniffer import PacketSniffer, FileAnalyzer
from src.deepseek_analyzer import DeepSeekAnalyzer

# Page config
st.set_page_config(
    page_title="AI Intrusion Detection System",
    page_icon="🛡️",
    layout="wide"
)

# Initialize session state
if 'sniffer' not in st.session_state:
    st.session_state.sniffer = PacketSniffer()
    st.session_state.sniffer.load_model()
    
if 'file_analyzer' not in st.session_state:
    st.session_state.file_analyzer = FileAnalyzer()
    
if 'analyzer' not in st.session_state:
    st.session_state.analyzer = DeepSeekAnalyzer()
    
if 'detection_active' not in st.session_state:
    st.session_state.detection_active = False
    
if 'thread' not in st.session_state:
    st.session_state.thread = None
    
if 'file_analysis_results' not in st.session_state:
    st.session_state.file_analysis_results = []
    
if 'last_analysis' not in st.session_state:
    st.session_state.last_analysis = None
    
if 'api_key_provided' not in st.session_state:
    st.session_state.api_key_provided = False

# Custom CSS
st.markdown("""
<style>
    .main-header {
        text-align: center;
        padding: 1rem;
        background: linear-gradient(90deg, #1e3c2c, #0a1f1a);
        border-radius: 10px;
        margin-bottom: 2rem;
    }
    .alert-box {
        padding: 1rem;
        border-radius: 5px;
        margin: 0.5rem 0;
        border-left: 4px solid;
    }
    .critical { border-color: #ff4b4b; background-color: #2a1a1a; }
    .high { border-color: #ffa64b; background-color: #2a241a; }
    .medium { border-color: #ffd24b; background-color: #2a2a1a; }
    .low { border-color: #4bff4b; background-color: #1a2a1a; }
    .metric-card {
        background: linear-gradient(135deg, #1a2a2a, #0f1f1a);
        padding: 1.5rem;
        border-radius: 10px;
        text-align: center;
        border: 1px solid #2a4a3a;
    }
    .stButton button {
        width: 100%;
        background: #1a3a2a;
        color: #9eff9e;
        border: 1px solid #2a4a3a;
    }
    .stButton button:hover {
        background: #2a4a3a;
        border-color: #f0b823;
    }
    .file-upload-area {
        border: 2px dashed #2a4a3a;
        padding: 2rem;
        border-radius: 10px;
        text-align: center;
        background: #0f1f1a;
        margin: 1rem 0;
    }
    .risk-meter {
        width: 100%;
        height: 20px;
        background: linear-gradient(90deg, #00ff00, #ffff00, #ff0000);
        border-radius: 10px;
        margin: 10px 0;
    }
    .hash-box {
        font-family: monospace;
        background: #0a1a1a;
        padding: 5px;
        border-radius: 3px;
        border: 1px solid #2a4a3a;
    }
    .ai-box {
        background: linear-gradient(135deg, #1a3a2a, #0f2a1f);
        padding: 2rem;
        border-radius: 10px;
        border-left: 6px solid #f0b823;
        margin: 1.5rem 0;
        box-shadow: 0 4px 15px rgba(0,0,0,0.3);
    }
    .context-text {
        background: #0f1f1a;
        padding: 1.5rem;
        border-radius: 8px;
        border-left: 4px solid #00ff00;
        margin: 1rem 0;
    }
    .prevention-text {
        background: #1a1f1a;
        padding: 1.5rem;
        border-radius: 8px;
        border-left: 4px solid #f0b823;
        margin: 1rem 0;
    }
</style>
""", unsafe_allow_html=True)

# Header
st.markdown('<div class="main-header">', unsafe_allow_html=True)
st.title("🛡️ AI-Powered Intrusion Detection System")
st.markdown("*Real-time network monitoring + DeepSeek AI Analysis*")
st.markdown('</div>', unsafe_allow_html=True)

# Create tabs
tab1, tab2 = st.tabs(["📁 File Upload Analysis", "📡 Live Detection"])

# ===== TAB 1: File Upload Analysis (MAIN TAB) =====
with tab1:
    # Sidebar - Move API Key here
    with st.sidebar:
        st.image("https://img.icons8.com/fluency/96/artificial-intelligence.png", width=80)
        st.title("⚙️ Settings")
        
        st.markdown("### 🤖 DeepSeek AI")
        api_key = st.text_input("API Key", type="password", 
                               placeholder="Enter your API key",
                               help="Get from platform.deepseek.com")
        
        if api_key:
            st.session_state.analyzer.api_key = api_key
            st.session_state.analyzer.mock_mode = False
            st.session_state.api_key_provided = True
            st.success("✅ AI Analysis ACTIVE")
            st.info("Context & Prevention will appear below")
        else:
            st.session_state.api_key_provided = False
            st.warning("⚠️ AI Analysis DISABLED")
            st.info("Add API key to see Context & Prevention")
        
        st.divider()
        st.markdown("### 📊 System Info")
        st.markdown("**Mode:** Simulation")
        st.markdown("**Status:** Ready")
    
    # Main content
    st.markdown("## 📁 File Upload Analysis")
    st.markdown("Upload files to detect malicious patterns")
    
    # File uploader
    with st.container():
        st.markdown('<div class="file-upload-area">', unsafe_allow_html=True)
        uploaded_file = st.file_uploader(
            "Choose a file to analyze", 
            type=['js', 'php', 'py', 'sql', 'txt', 'csv', 'log', 'ps1', 'exe', 'dll'],
            help="Upload any file for analysis"
        )
        st.markdown('</div>', unsafe_allow_html=True)
    
    if uploaded_file is not None:
        # Save file temporarily
        with tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(uploaded_file.name)[1]) as tmp_file:
            tmp_file.write(uploaded_file.getvalue())
            tmp_path = tmp_file.name
        
        with st.spinner("🔍 Analyzing file..."):
            # Local analysis
            analysis_result = st.session_state.file_analyzer.analyze_file(tmp_path, uploaded_file.name)
            st.session_state.file_analysis_results.append(analysis_result)
            st.session_state['current_file'] = analysis_result
            
            # ALWAYS get AI analysis if API key is provided
            if st.session_state.api_key_provided:
                deepseek_input = {
                    'timestamp': analysis_result['timestamp'],
                    'src_ip': 'FILE_UPLOAD',
                    'dst_ip': 'SYSTEM',
                    'protocol': 'FILE',
                    'confidence': analysis_result['risk_score'] / 100,
                    'attack_type': 'File Analysis',
                    'features': {
                        'filename': analysis_result['filename'],
                        'risk_score': analysis_result['risk_score'],
                        'suspicious_patterns': analysis_result.get('suspicious_patterns', [])
                    }
                }
                ai_result = st.session_state.analyzer.analyze_alert(deepseek_input)
                st.session_state['last_analysis'] = ai_result
        
        # Display basic file info
        col1, col2, col3 = st.columns(3)
        
        with col1:
            risk = analysis_result['risk_level']
            if risk == 'CRITICAL':
                st.error(f"### ⚠️ {risk}")
            elif risk == 'HIGH':
                st.warning(f"### ⚠️ {risk}")
            else:
                st.info(f"### {risk}")
            st.markdown(f"**Score:** {analysis_result['risk_score']}/100")
        
        with col2:
            st.markdown("### 📄 File Info")
            st.markdown(f"**Name:** {analysis_result['filename']}")
            st.markdown(f"**Size:** {analysis_result['file_size']} bytes")
            st.markdown(f"**Entropy:** {analysis_result['entropy']:.2f}")
        
        with col3:
            st.markdown("### 🔑 Hashes")
            st.markdown(f"**MD5:** `{analysis_result['hash']['md5'][:10]}...`")
            st.markdown(f"**SHA1:** `{analysis_result['hash']['sha1'][:10]}...`")
        
        # Show suspicious patterns
        if analysis_result['suspicious_patterns']:
            st.markdown("### 🔍 Detected Patterns")
            df = pd.DataFrame(analysis_result['suspicious_patterns'])
            st.dataframe(df, use_container_width=True)
        
        # ===== AI ANALYSIS SECTION - SHOWS ONLY WHEN API KEY IS PROVIDED =====
        if st.session_state.api_key_provided and 'last_analysis' in st.session_state:
            st.markdown("---")
            st.markdown('<div class="ai-box">', unsafe_allow_html=True)
            
            ai = st.session_state.last_analysis
            
            # Header
            st.markdown("## 🤖 DeepSeek AI Analysis")
            
            # Threat Level with color
            threat = ai.get('threat_level', analysis_result['risk_level'])
            if threat == 'CRITICAL':
                st.error(f"### ⚠️ THREAT LEVEL: {threat}")
            elif threat == 'HIGH':
                st.warning(f"### ⚠️ THREAT LEVEL: {threat}")
            else:
                st.info(f"### THREAT LEVEL: {threat}")
            
            # Attack Type
            attack = ai.get('attack_type', 'Unknown')
            st.success(f"### 🎯 Attack Type: {attack}")
            
            # CONTEXT SECTION
            st.markdown("### 📋 Context")
            st.markdown('<div class="context-text">', unsafe_allow_html=True)
            context = ai.get('context', 'No context available')
            
            # Format and display context as bullet points
            if isinstance(context, str):
                # Split into sentences
                sentences = context.replace('. ', '.\n').split('\n')
                for sentence in sentences:
                    if sentence.strip():
                        clean = sentence.strip()
                        # Remove numbering if present
                        if clean and clean[0].isdigit() and '.' in clean[:3]:
                            clean = clean[clean.find('.')+1:].strip()
                        st.markdown(f"• {clean}")
            st.markdown('</div>', unsafe_allow_html=True)
            
            # PREVENTION SECTION
            st.markdown("### 🛡️ Prevention")
            st.markdown('<div class="prevention-text">', unsafe_allow_html=True)
            prevention = ai.get('prevention', 'No prevention steps available')
            
            # Format and display prevention as numbered steps
            if isinstance(prevention, str):
                # Split into steps
                steps = prevention.replace('. ', '.\n').split('\n')
                for i, step in enumerate(steps, 1):
                    if step.strip():
                        clean = step.strip()
                        # Remove numbering if present
                        if clean and clean[0].isdigit() and '.' in clean[:3]:
                            clean = clean[clean.find('.')+1:].strip()
                        st.markdown(f"**{i}.** {clean}")
            st.markdown('</div>', unsafe_allow_html=True)
            
            st.markdown('</div>', unsafe_allow_html=True)
        
        # Clean up
        os.unlink(tmp_path)

# ===== TAB 2: Live Detection (Simplified) =====
with tab2:
    st.markdown("## 📡 Live Network Detection")
    
    col1, col2 = st.columns([1, 4])
    with col1:
        if st.button("▶️ START", use_container_width=True):
            if not st.session_state.detection_active:
                st.session_state.detection_active = True
                thread = threading.Thread(target=st.session_state.sniffer.start_sniffing)
                thread.daemon = True
                thread.start()
                st.success("Started!")
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        stats = st.session_state.sniffer.get_stats()
        st.metric("Packets", stats['packet_count'])
    with col2:
        st.metric("Alerts", stats['alert_count'])
    with col3:
        st.metric("Rate", f"{stats['packet_rate']}/s")
    with col4:
        st.metric("IPs", stats['unique_ips'])

# Auto-refresh
if st.session_state.detection_active:
    time.sleep(2)
    st.rerun()
