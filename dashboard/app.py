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
</style>
""", unsafe_allow_html=True)

# Header
st.markdown('<div class="main-header">', unsafe_allow_html=True)
st.title("🛡️ AI-Powered Intrusion Detection System")
st.markdown("*Real-time network monitoring + File analysis with DeepSeek AI*")
st.markdown('</div>', unsafe_allow_html=True)

# Create tabs for different features
tab1, tab2, tab3 = st.tabs(["📡 Live Network Detection", "📁 File Upload Analysis", "📊 Threat Intelligence"])

# ===== TAB 1: Live Network Detection =====
with tab1:
    # Sidebar
    with st.sidebar:
        st.image("https://img.icons8.com/fluency/96/artificial-intelligence.png", width=80)
        st.title("Control Panel")
        
        st.markdown("### 🎮 Detection Controls")
        
        col1, col2 = st.columns(2)
        with col1:
            if st.button("▶️ START", use_container_width=True):
                if not st.session_state.detection_active:
                    st.session_state.detection_active = True
                    thread = threading.Thread(target=st.session_state.sniffer.start_sniffing)
                    thread.daemon = True
                    thread.start()
                    st.success("✅ Detection started!")
                    
        with col2:
            if st.button("⏹️ STOP", use_container_width=True):
                st.session_state.sniffer.stop_sniffing()
                st.session_state.detection_active = False
                st.warning("🛑 Detection stopped")
        
        st.divider()
        
        st.markdown("### 🤖 DeepSeek AI Settings")
        api_key = st.text_input("API Key (optional)", type="password", 
                               help="Get from platform.deepseek.com")
        if api_key:
            st.session_state.analyzer.api_key = api_key
            st.session_state.analyzer.mock_mode = False
            st.success("✅ API Key set")
        
        st.divider()
        
        st.markdown("### 📊 System Status")
        if st.session_state.detection_active:
            st.markdown("🟢 **Active**")
        else:
            st.markdown("🔴 **Inactive**")
        
        st.markdown(f"📡 **Interface:** {st.session_state.sniffer.interface}")
        st.markdown(f"📦 **Mode:** {'Simulation' if st.session_state.sniffer.simulation_mode else 'Live'}")

    # Main dashboard
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        stats = st.session_state.sniffer.get_stats()
        st.markdown('<div class="metric-card">', unsafe_allow_html=True)
        st.metric("Packets Captured", stats['packet_count'])
        st.markdown('</div>', unsafe_allow_html=True)

    with col2:
        st.markdown('<div class="metric-card">', unsafe_allow_html=True)
        st.metric("Active Alerts", stats['alert_count'])
        st.markdown('</div>', unsafe_allow_html=True)

    with col3:
        st.markdown('<div class="metric-card">', unsafe_allow_html=True)
        st.metric("Packet Rate", f"{stats['packet_rate']}/s")
        st.markdown('</div>', unsafe_allow_html=True)

    with col4:
        st.markdown('<div class="metric-card">', unsafe_allow_html=True)
        st.metric("Unique IPs", stats['unique_ips'])
        st.markdown('</div>', unsafe_allow_html=True)

    # Charts
    st.markdown("### 📈 Live Traffic Analysis")
    col1, col2 = st.columns(2)

    with col1:
        # Get protocol distribution from stats
        stats = st.session_state.sniffer.get_stats()
        protocols = stats.get('protocols', {'TCP': 25, 'UDP': 10, 'ICMP': 5, 'Other': 2})
        
        fig = go.Figure(data=[go.Pie(
            labels=list(protocols.keys()),
            values=list(protocols.values()),
            hole=0.4,
            marker_colors=['#00ff00', '#ffaa00', '#ff4b4b', '#888888']
        )])
        fig.update_layout(
            title="Protocol Distribution",
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font_color='#9eff9e'
        )
        st.plotly_chart(fig, use_container_width=True)

    with col2:
        # Get packet rates from stats
        stats = st.session_state.sniffer.get_stats()
        rates = stats.get('packet_rates', list(np.random.randint(5, 30, 20)))
        
        fig = go.Figure(data=[go.Scatter(
            y=rates,
            mode='lines+markers',
            line=dict(color='#00ff00', width=2),
            marker=dict(color='#f0b823', size=6)
        )])
        fig.update_layout(
            title="Packet Rate (last 20 samples)",
            xaxis_title="Time",
            yaxis_title="Packets/sec",
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font_color='#9eff9e'
        )
        st.plotly_chart(fig, use_container_width=True)

    # Alerts section
    st.markdown("### 🚨 Recent Alerts")

    alerts = st.session_state.sniffer.get_alerts()

    if alerts:
        for i, alert in enumerate(reversed(alerts[-10:])):
            confidence = alert.get('confidence', 0.5)
            
            if confidence > 0.8:
                level = "critical"
                level_text = "CRITICAL"
            elif confidence > 0.6:
                level = "high"
                level_text = "HIGH"
            else:
                level = "medium"
                level_text = "MEDIUM"
            
            attack_type = alert.get('attack_type', 'Intrusion Detection')
            
            col1, col2, col3 = st.columns([3, 2, 1])
            
            with col1:
                st.markdown(f"**{alert['timestamp']}**")
                st.markdown(f"📍 {alert['src_ip']} → {alert['dst_ip']}")
                st.markdown(f"**Type:** {attack_type}")
            
            with col2:
                st.markdown(f"📡 Protocol: {alert['protocol']}")
                st.markdown(f"🎯 Confidence: {alert['confidence']:.1%}")
            
            with col3:
                st.markdown(f"**{level_text}**")
                if st.button(f"🔍 Analyze", key=f"analyze_{i}"):
                    with st.spinner("Analyzing with DeepSeek..."):
                        analysis = st.session_state.analyzer.analyze_alert(alert)
                        st.session_state['last_analysis'] = analysis
            
            st.divider()
    else:
        st.info("No alerts detected yet. Start the detection system to begin monitoring.")

# ===== TAB 2: File Upload Analysis =====
with tab2:
    st.markdown("## 📁 Malicious File Detection")
    st.markdown("Upload files to analyze for malware, webshells, and suspicious patterns")
    
    # File uploader
    with st.container():
        st.markdown('<div class="file-upload-area">', unsafe_allow_html=True)
        uploaded_file = st.file_uploader(
            "Choose a file to analyze", 
            type=['js', 'php', 'py', 'ps1', 'sql', 'log', 'txt', 'csv', 'exe', 'dll', 'pdf', 'doc', 'zip', 'pcap'],
            help="Upload any file type for analysis. JavaScript, PHP, Python, PowerShell, SQL files will be analyzed for malicious patterns."
        )
        st.markdown('</div>', unsafe_allow_html=True)
    
    if uploaded_file is not None:
        # Save uploaded file temporarily
        with tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(uploaded_file.name)[1]) as tmp_file:
            tmp_file.write(uploaded_file.getvalue())
            tmp_path = tmp_file.name
        
        # Show analysis progress
        with st.spinner("🔍 Analyzing file for malicious content..."):
            # Analyze the file
            analysis_result = st.session_state.file_analyzer.analyze_file(tmp_path, uploaded_file.name)
            st.session_state.file_analysis_results.append(analysis_result)
            
            # Also analyze with DeepSeek
            deepseek_analysis = st.session_state.analyzer.analyze_alert({
                'timestamp': analysis_result['timestamp'],
                'src_ip': 'FILE_UPLOAD',
                'dst_ip': 'LOCAL_SYSTEM',
                'protocol': 'FILE',
                'confidence': analysis_result['risk_score'] / 100,
                'attack_type': analysis_result.get('attack_summary', 'Unknown'),
                'features': analysis_result
            })
            st.session_state['last_analysis'] = deepseek_analysis
        
        # Display results
        col1, col2, col3 = st.columns(3)
        
        with col1:
            risk_color = "red" if analysis_result['risk_level'] in ['CRITICAL', 'HIGH'] else "orange" if analysis_result['risk_level'] == 'MEDIUM' else "green"
            st.markdown(f"### Risk Level: :{risk_color}[**{analysis_result['risk_level']}**]")
            st.markdown(f"**Risk Score:** {analysis_result['risk_score']}/100")
            
            # Risk meter
            st.markdown(f"""
            <div style="width:100%; height:20px; background:#ddd; border-radius:10px;">
                <div style="width:{analysis_result['risk_score']}%; height:20px; 
                     background:{'#ff0000' if analysis_result['risk_score']>70 else '#ffaa00' if analysis_result['risk_score']>30 else '#00ff00'}; 
                     border-radius:10px;"></div>
            </div>
            """, unsafe_allow_html=True)
        
        with col2:
            st.markdown("### File Details")
            st.markdown(f"**Filename:** {analysis_result['filename']}")
            st.markdown(f"**Size:** {analysis_result['file_size']:,} bytes")
            st.markdown(f"**Type:** {analysis_result['file_type'].get('mime_type', 'Unknown')}")
            st.markdown(f"**Extension:** {analysis_result['file_type'].get('extension', 'Unknown')}")
            st.markdown(f"**Entropy:** {analysis_result['entropy']:.2f} (higher = more suspicious)")
        
        with col3:
            st.markdown("### File Hashes")
            st.markdown(f"**MD5:** `{analysis_result['hash']['md5'][:16]}...`")
            st.markdown(f"**SHA1:** `{analysis_result['hash']['sha1'][:16]}...`")
            st.markdown(f"**SHA256:** `{analysis_result['hash']['sha256'][:16]}...`")
        
        # Suspicious patterns found
        if analysis_result['suspicious_patterns']:
            st.markdown("### 🔍 Suspicious Patterns Detected")
            patterns_df = pd.DataFrame(analysis_result['suspicious_patterns'])
            st.dataframe(patterns_df, use_container_width=True)
        
        # Clean up temp file
        os.unlink(tmp_path)
    
    # Show analysis history
    if st.session_state.file_analysis_results:
        st.markdown("### 📋 Recent File Analyses")
        history_df = pd.DataFrame([
            {
                'Time': r['timestamp'][11:19],
                'Filename': r['filename'],
                'Risk Level': r['risk_level'],
                'Risk Score': r['risk_score'],
                'Size': f"{r['file_size']/1024:.1f} KB"
            }
            for r in st.session_state.file_analysis_results[-10:]
        ])
        st.dataframe(history_df, use_container_width=True)

# ===== TAB 3: Threat Intelligence =====
with tab3:
    st.markdown("## 🌐 Threat Intelligence Dashboard")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("### Known Malware Hashes")
        st.markdown("""
        - **EICAR Test Virus**: `275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f`
        - More hashes can be added to the database
        """)
        
        st.markdown("### Suspicious Patterns Database")
        patterns_df = pd.DataFrame([
            {'Pattern Type': 'JavaScript Malware', 'Example': 'eval(), atob(), unescape()', 'Severity': 'HIGH'},
            {'Pattern Type': 'PHP WebShell', 'Example': 'system(), exec(), eval()', 'Severity': 'CRITICAL'},
            {'Pattern Type': 'SQL Injection', 'Example': 'UNION SELECT, DROP TABLE', 'Severity': 'MEDIUM'},
            {'Pattern Type': 'Python Malware', 'Example': 'subprocess, eval(), __import__', 'Severity': 'HIGH'},
            {'Pattern Type': 'PowerShell Malware', 'Example': 'IEX, DownloadString, Invoke-Expression', 'Severity': 'HIGH'},
        ])
        st.dataframe(patterns_df, use_container_width=True)
    
    with col2:
        st.markdown("### Detection Statistics")
        
        # File analysis stats
        file_count = len(st.session_state.file_analysis_results)
        if file_count > 0:
            critical_count = sum(1 for r in st.session_state.file_analysis_results if r['risk_level'] == 'CRITICAL')
            high_count = sum(1 for r in st.session_state.file_analysis_results if r['risk_level'] == 'HIGH')
            medium_count = sum(1 for r in st.session_state.file_analysis_results if r['risk_level'] == 'MEDIUM')
            low_count = sum(1 for r in st.session_state.file_analysis_results if r['risk_level'] == 'LOW')
            
            fig = go.Figure(data=[go.Bar(
                x=['Critical', 'High', 'Medium', 'Low'],
                y=[critical_count, high_count, medium_count, low_count],
                marker_color=['#ff4b4b', '#ffa64b', '#ffd24b', '#4bff4b']
            )])
            fig.update_layout(title="File Analysis Results by Risk Level")
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No files analyzed yet. Upload files in the File Analysis tab.")
            
        # Live network stats
        st.markdown("### Live Network Stats")
        stats = st.session_state.sniffer.get_stats()
        st.markdown(f"**Total Packets:** {stats['packet_count']}")
        st.markdown(f"**Total Alerts:** {stats['alert_count']}")
        st.markdown(f"**Unique IPs Seen:** {stats['unique_ips']}")

# ===== DeepSeek Analysis Display (FIXED - NO ACTIONS, NO N/A) =====
if 'last_analysis' in st.session_state and st.session_state.last_analysis:
    st.markdown("---")
    st.markdown("## 🤖 DeepSeek AI Analysis Results")
    
    analysis = st.session_state.last_analysis
    
    # Create columns for better layout
    col1, col2 = st.columns(2)
    
    with col1:
        # Threat Level with color
        threat = analysis.get('threat_level', 'MEDIUM')
        if threat == 'CRITICAL':
            st.error(f"### ⚠️ THREAT LEVEL: {threat}")
        elif threat == 'HIGH':
            st.warning(f"### ⚠️ THREAT LEVEL: {threat}")
        else:
            st.info(f"### THREAT LEVEL: {threat}")
    
    with col2:
        # Attack Type
        st.success(f"### 🎯 Attack Type: {analysis.get('attack_type', 'Unknown')}")
    
    # CONTEXT SECTION
    st.markdown("### 📋 Context - What is happening?")
    context = analysis.get('context', 'No context available')
    
    # Clean and display context as bullet points
    if isinstance(context, str):
        # Try to split into sentences
        sentences = context.replace('. ', '.\n').split('\n')
        for sentence in sentences:
            if sentence.strip():
                clean = sentence.strip()
                if clean and clean[0].isdigit() and '.' in clean[:3]:
                    clean = clean[clean.find('.')+1:].strip()
                st.markdown(f"• {clean}")
    
    # PREVENTION SECTION
    st.markdown("### 🛡️ Prevention - What should you do?")
    prevention = analysis.get('prevention', 'No prevention steps available')
    
    # Clean and display prevention as numbered steps
    if isinstance(prevention, str):
        # Try to split into steps
        steps = prevention.replace('. ', '.\n').split('\n')
        for i, step in enumerate(steps, 1):
            if step.strip():
                clean = step.strip()
                if clean and clean[0].isdigit() and '.' in clean[:3]:
                    clean = clean[clean.find('.')+1:].strip()
                st.markdown(f"**{i}.** {clean}")
    
    # Simple footer
    st.markdown("---")
    st.caption("Follow these prevention steps to protect your system")

# Auto-refresh for live detection
if st.session_state.detection_active:
    time.sleep(2)
    st.rerun()