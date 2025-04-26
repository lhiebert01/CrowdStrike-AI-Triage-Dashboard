import streamlit as st
import pandas as pd
import datetime
import os
import requests
import openai
from dotenv import dotenv_values

# Load API keys from Streamlit secrets (cloud) or .env file (local)
try:
    # First try loading from streamlit secrets
    GOOGLE_KEY = st.secrets.get("GOOGLE_API_KEY", "")
    OPENAI_KEY = st.secrets.get("OPENAI_API_KEY", "")
    
    # If both are empty, try loading from .env
    if not (GOOGLE_KEY or OPENAI_KEY):
        # Load and parse .env
        env_path = os.path.join(os.path.dirname(__file__), ".env")
        config = dotenv_values(env_path)
        # Trim API keys
        GOOGLE_KEY = (config.get("GOOGLE_API_KEY") or "").strip()
        OPENAI_KEY = (config.get("OPENAI_API_KEY") or "").strip()
        
except Exception as e:
    # Log error for debugging
    print(f"Error loading API keys: {e}")
    # Fall back to empty keys if all loading methods fail
    GOOGLE_KEY = ""
    OPENAI_KEY = ""
    
# Assign OpenAI API key if available
if OPENAI_KEY:
    openai.api_key = OPENAI_KEY

# App config (must be first Streamlit command)
st.set_page_config(page_title="CrowdStrike Enhanced EDR", layout="wide")

# Compact AI Engine Information
model_status = f"**MODELS:** Gemini {'✅' if GOOGLE_KEY else '❌'} | OpenAI {'✅' if OPENAI_KEY else '❌'}"
st.sidebar.markdown(model_status)

# AI helpers
def ask_gemini(prompt):
    url = "https://generativelanguage.googleapis.com/v1/models/gemini-2.0-flash-001:generateContent"
    headers = {"Content-Type":"application/json", "x-goog-api-key":GOOGLE_KEY}
    body = {"contents":[{"parts":[{"text":prompt}]}]}
    r = requests.post(url, headers=headers, json=body, timeout=20)  # Increased timeout
    r.raise_for_status()
    j = r.json()
    return j["candidates"][0]["content"]["parts"][0]["text"]

def ask_openai(prompt):
    # New OpenAI client interface (v1.0+)
    client = openai.OpenAI(api_key=OPENAI_KEY)
    resp = client.chat.completions.create(
        model="gpt-3.5-turbo",
        messages=[
            {"role":"system","content":"You are a helpful SOC assistant."},
            {"role":"user","content":prompt}
        ],
        timeout=15  # Increased timeout
    )
    return resp.choices[0].message.content

def ask_ai(prompt):
    # Try both AI providers and report errors
    errors = []
    # Attempt OpenAI
    if OPENAI_KEY:
        try:
            return ask_openai(prompt)
        except Exception as e:
            errors.append(f"OpenAI error: {e}")
    # Attempt Gemini
    if GOOGLE_KEY:
        try:
            return ask_gemini(prompt)
        except Exception as e:
            errors.append(f"Gemini error: {e}")
    # Return any collected errors
    if errors:
        return " | ".join(errors)
    return "Error: No valid AI key available."

# Simulated alerts
def get_alerts():
    now = datetime.datetime.now()
    return [
        {"id":"A1","host":"FIN-SRV-01","severity":10,
         "timestamp":now - datetime.timedelta(minutes=30),
         "title":"Ransomware detected","tactic":"Execution",
         "technique":"T1486","triggering_file":"powershell.exe",
         "iocs":["e3b0...855","185.141.25.178"],
         "command_line":"powershell -enc ...",
         "process_tree":[{"pid":100, "name":"explorer.exe"},{"pid":101,"name":"powershell.exe","ppid":100}],
         "operations":{"network":[{"proto":"TCP","dest":"185.141.25.178:443"}],
                       "disk":[{"op":"write","path":"C:/temp/eicar.txt"}],
                       "registry":[]},
         "status":"New"},
        {"id":"A2","host":"DEV-WS-03","severity":8,
         "timestamp":now - datetime.timedelta(hours=2),
         "title":"Credential Dumping","tactic":"Credential Access",
         "technique":"T1003.001","triggering_file":"lsass.exe",
         "iocs":["mimikatz-behav"],
         "command_line":"lsass.exe -memdump",
         "process_tree":[{"pid":200,"name":"svchost.exe"},{"pid":201,"name":"lsass.exe","ppid":200}],
         "operations":{"network":[],"disk":[],"registry":[]},
         "status":"In Progress"},
        {"id":"A3","host":"HR-WS-05","severity":7,
         "timestamp":now - datetime.timedelta(minutes=45),
         "title":"Malicious Domain C2","tactic":"Command and Control",
         "technique":"T1071.001","triggering_file":"chrome.exe",
         "iocs":["badguy-updates.ru"],
         "command_line":"chrome --url http://badguy-updates.ru",
         "process_tree":[{"pid":300,"name":"explorer.exe"},{"pid":301,"name":"chrome.exe","ppid":300}],
         "operations":{"network":[{"proto":"HTTP","dest":"badguy-updates.ru"}],
                       "disk":[],"registry":[]},
         "status":"Monitor"}
    ]

# UI state
if 'chat_history' not in st.session_state:
    st.session_state.chat_history = []

# Sidebar
st.sidebar.title("CrowdStrike Enhanced EDR")

# Designer attribution
st.sidebar.markdown("---")
st.sidebar.markdown("<small>Designed by: <a href='https://www.linkedin.com/in/lindsayhiebert/' target='_blank'>Lindsay Hiebert</a></small>", unsafe_allow_html=True)

# View Mode at top of sidebar
view_mode = st.sidebar.radio("View Mode", ['Triage Dashboard','AI Chat'])

# Alert filters
st.sidebar.markdown("### Filters & Grouping")
alerts = pd.DataFrame(get_alerts())
min_sev, max_sev = st.sidebar.slider("Severity", 0, 10, (0,10))
hosts = alerts['host'].unique().tolist()
sel_hosts = st.sidebar.multiselect("Hosts", hosts, default=hosts)
techs = alerts['technique'].unique().tolist()
sel_tech = st.sidebar.multiselect("Techniques", techs, default=techs)
# Search input with examples
search_input = st.sidebar.text_input(
    "Search text",
    placeholder="e.g. ransomware, FIN-SRV-01, T1071.001",
    help="Search across all alert fields (partial matches allowed)"
)
st.sidebar.info("Examples: ransomware, FIN-SRV-01, 185.141.25.178, powershell.exe")
group_by = st.sidebar.selectbox("Group by", ['None','host','technique','triggering_file','command_line'])

# AI Chat view
if view_mode=='AI Chat':
    # Add footer with attribution
    st.markdown("---")
    st.markdown("<div style='text-align:center; color:gray; font-size:0.8em;'>Designed by <a href='https://www.linkedin.com/in/lindsayhiebert/' target='_blank'>Lindsay Hiebert</a> | Powered by Google Gemini and OpenAI</div>", unsafe_allow_html=True)
    # Initialize chat context if not present
    if 'context_selected' not in st.session_state:
        st.session_state.context_selected = None
    
    # Enhanced header with CrowdStrike branding
    st.markdown("""
    <div style='background-color:#DD0011; padding:10px; border-radius:5px; margin-bottom:10px'>
        <h2 style='color:white; text-align:center'>🔍 CrowdStrike Enhanced Endpoint Detection & Response</h2>
        <h4 style='color:white; text-align:center'>Enabling Faster, Better, Smarter Endpoint Security, Triage and Effective Response</h4>
    </div>
    """, unsafe_allow_html=True)
    
    # Left sidebar for quick links and right main chat area
    col1, col2 = st.columns([1, 3])
    
    with col1:
        st.markdown("### Quick Resources")
        
        # Documentation links
        st.markdown("#### 📚 Documentation")
        st.markdown("[CrowdStrike Falcon Documentation](https://falcon.crowdstrike.com/documentation/)")  
        st.markdown("[MITRE ATT&CK Framework](https://attack.mitre.org/)")
        st.markdown("[Threat Intelligence Portal](https://falcon.crowdstrike.com/intelligence)")  
        
        # Contextual help buttons
        st.markdown("#### 🛠️ Contextual Help")
        context_options = {
            "Alert Triage": "Information about investigating and triaging alerts",
            "Incident Response": "Steps and procedures for responding to security incidents",
            "Threat Hunting": "Techniques and tools for proactive threat hunting",
            "IOC Analysis": "How to analyze and understand indicators of compromise",
            "Malware Analysis": "Tools and methods for analyzing malicious code"
        }
        
        for context, description in context_options.items():
            if st.button(context, help=description):
                st.session_state.context_selected = context
                if 'chat_history' not in st.session_state:
                    st.session_state.chat_history = []
                # Add context prompt to the chat
                prompt = f"Please provide guidance on CrowdStrike {context} best practices and workflows."
                st.session_state.chat_history.append((prompt, "Loading response...", True))  # True for concise
                # Modern rerun API
                st.rerun()
        
        # High-Priority Threats section
        st.markdown("#### ⚠️ High-Priority Threats")
        threat_examples = {
            "APT Groups (Fancy Bear/Cozy Bear)": "What are the key indicators of APT28/APT29 activity?",
            "Ransomware (Ryuk/Maze/BlackCat)": "How do I detect and respond to Ryuk ransomware?",
            "Credential Theft & Brute Force": "What are signs of credential theft in CrowdStrike?",
            "Data Exfiltration Techniques": "How to detect data exfiltration using CrowdStrike?",
            "Malicious Insider Activity": "What indicators suggest malicious insider threats?",
            "Living-off-the-Land Attacks": "How to identify living-off-the-land techniques?",
            "Supply Chain Compromises": "What are key indicators of supply chain attacks?"
        }
        
        # Sample questions section
        st.markdown("#### 💡 Common SOC Questions")
        sample_questions = [
            "How do I investigate a PowerShell execution alert?",
            "What are common C2 indicators in network traffic?",
            "Explain lateral movement detection techniques",
            "Show me a sample incident response playbook",
            "How to prioritize alerts by severity?",
            "What's the difference between IOA and IOC?",
            "Explain MITRE ATT&CK technique T1486"
        ]
        
        # Handle threat examples
        for threat, question in threat_examples.items():
            if st.button(threat, key=f"threat_{threat}"):
                if 'chat_history' not in st.session_state:
                    st.session_state.chat_history = []
                st.session_state.chat_history.append((question, "Loading response...", True))  # True for concise
                # Modern rerun API
                st.rerun()
                
        # Handle sample questions
        for q in sample_questions:
            if st.button(q, key=f"sample_{q}"):
                if 'chat_history' not in st.session_state:
                    st.session_state.chat_history = []
                st.session_state.chat_history.append((q, "Loading response...", True))  # True for concise
                # Modern rerun API
                st.rerun()
    
    with col2:
        # Chat header with context indicator
        if st.session_state.context_selected:
            st.markdown(f"#### Current Context: {st.session_state.context_selected}")
            if st.button("Clear Context"):
                st.session_state.context_selected = None
        
        # Chat input area
        user_input = st.text_area("Enter your security question:", 
                                height=100, 
                                placeholder="e.g., How do I analyze this PowerShell command for malicious behavior?")
        
        # Chat controls
        col_send, col_clear = st.columns([1, 1])
        with col_send:
            send_pressed = st.button("Send Question", use_container_width=True)
        with col_clear:
            if st.button("Clear Chat History", use_container_width=True):
                st.session_state.chat_history = []
                st.rerun()
        
        # Process inputs
        if send_pressed and user_input:
            # Add context to the prompt if selected
            full_prompt = user_input
            if st.session_state.context_selected:
                full_prompt = f"[Context: {st.session_state.context_selected}] {user_input}"
            
            # Add to history immediately with loading state
            if 'chat_history' not in st.session_state:
                st.session_state.chat_history = []
            
            st.session_state.chat_history.append((user_input, "Generating response..."))
            # Get AI response in background
            with st.spinner("SOC Assistant is thinking..."):
                full_prompt_concise = full_prompt + " (Please provide a concise response)"
                response = ask_ai(full_prompt_concise)
            # Update the last message with the actual response and a flag for concise mode
            st.session_state.chat_history[-1] = (user_input, response, True)  # True = concise mode
        
        # Process any "Loading" responses
        for i, (q, a, *rest) in enumerate(list(st.session_state.chat_history)):
            if a in ["Loading response...", "Generating response..."]:
                with st.spinner("SOC Assistant is thinking..."):
                    full_q = q + " (Please provide a concise response)"
                    response = ask_ai(full_q)
                # Update in place with concise flag
                st.session_state.chat_history[i] = (q, response, True)  # True = concise mode
        
        # Add button to download chat history
        if 'chat_history' in st.session_state and st.session_state.chat_history:
            chat_text = "# CrowdStrike SOC AI Assistant Conversation\n\n"
            for q, a, *rest in st.session_state.chat_history:
                chat_text += f"## Question: {q}\n\n{a}\n\n---\n\n"
            
            # Create download button
            st.download_button(
                label="📥 Download Conversation",
                data=chat_text,
                file_name=f"crowdstrike-soc-chat-{datetime.datetime.now().strftime('%Y-%m-%d-%H%M')}.md",
                mime="text/markdown"
            )
        
        # Display chat history (newest first)
        st.markdown("### Conversation History")
        chat_container = st.container()
        
        with chat_container:
            if 'chat_history' in st.session_state and st.session_state.chat_history:
                # Reverse the history to show newest messages first
                for q, a, *rest in reversed(st.session_state.chat_history):
                    is_concise = len(rest) > 0 and rest[0] is True
                    message_id = f"msg_{hash(q)}"
                    
                    # User message with CrowdStrike styling
                    st.markdown(f"""
                    <div style='background-color:#f0f0f0; color:#111111; padding:10px; border-radius:5px; margin-bottom:10px'>
                        <strong style='color:#000000;'>🔍 SOC Analyst:</strong> <span style='color:#000000;'>{q}</span>
                    </div>
                    """, unsafe_allow_html=True)
                    
                    # AI response with CrowdStrike styling
                    st.markdown(f"""
                    <div style='background-color:#f9f9f9; color:#111111; padding:10px; border-radius:5px; border-left:3px solid #DD0011; margin-bottom:20px'>
                        <strong style='color:#000000;'>🤖 CrowdStrike AI:</strong> <span style='color:#000000;'>{a}</span>
                    </div>
                    """, unsafe_allow_html=True)
                    
                    # Add show more details button for concise responses
                    if is_concise:
                        if st.button(f"🔍 Show More Details", key=f"more_{message_id}"):
                            with st.spinner("Getting detailed response..."):
                                detailed_prompt = q + " (Please provide a detailed, comprehensive response)"
                                detailed_response = ask_ai(detailed_prompt)
                                st.markdown(f"""
                                <div style='background-color:#f9f9f9; color:#111111; padding:10px; border-radius:5px; border-left:3px solid #007BFF; margin-bottom:20px'>
                                    <strong style='color:#000000;'>🔍 Detailed Response:</strong> <span style='color:#000000;'>{detailed_response}</span>
                                </div>
                                """, unsafe_allow_html=True)
                                
                    st.markdown("<hr>", unsafe_allow_html=True)
            else:
                st.info("Start a conversation with the CrowdStrike SOC AI Assistant using the input field above or select a sample question.")
    
    st.stop()

# Apply filters
df = alerts[(alerts.severity.between(min_sev,max_sev)) & (alerts.host.isin(sel_hosts)) & (alerts.technique.isin(sel_tech))]
# Clean search: remove surrounding quotes and whitespace
search_query = search_input.strip().strip('"').strip("'") if search_input else ""
if search_query:
    df = df[df.apply(lambda r: search_query.lower() in str(r.values).lower(), axis=1)]

st.header("🚨 CrowdStrike Enhanced EDR - Triage Dashboard")

# Add footer with attribution
st.markdown("---")
st.markdown("<div style='text-align:center; color:gray; font-size:0.8em;'>Designed by <a href='https://www.linkedin.com/in/lindsayhiebert/' target='_blank'>Lindsay Hiebert</a> | Powered by Google Gemini and OpenAI</div>", unsafe_allow_html=True)

# Grouping
if group_by!='None':
    st.subheader(f"Alerts Grouped by {group_by}")
    
    # Group alerts but retain all fields
    grouped = df.groupby(group_by)
    
    # For each group, create an expandable section
    for name, group_df in grouped:
        with st.expander(f"{group_by}: {name} ({len(group_df)} alerts)"):
            # Display group statistics
            col1, col2 = st.columns([1, 3])
            with col1:
                st.metric("Alert Count", len(group_df))
                if 'severity' in group_df.columns:
                    st.metric("Avg Severity", f"{group_df['severity'].mean():.1f}")
            
            # Show the actual alerts in this group
            st.dataframe(
                group_df[['id', 'host', 'severity', 'title', 'technique', 'timestamp', 'status']]
                .sort_values('severity', ascending=False)
            )
            
            # Add a button to summarize alerts with AI (concise by default)
            if st.button(f"AI Summary for {name}", key=f"ai_{group_by}_{name}"):
                summary = ask_ai(f"Summarize these alerts grouped by {group_by}={name}: {group_df.to_dict('records')} (Please provide a concise response)")
                st.write(summary)
            
            # Option for detailed analysis
            if st.button(f"🔍 Detailed Analysis", key=f"detail_{group_by}_{name}"):
                detailed = ask_ai(f"Provide a detailed analysis and response recommendations for these alerts grouped by {group_by}={name}: {group_df.to_dict('records')}")
                st.write(detailed)
    
    # Stop here, don't show individual alert details
    st.stop()

# If no alerts after filtering, inform user and stop
if df.empty:
    st.warning("No alerts match the current filter criteria.")
    st.stop()

## No grouping: show queue + detail + AI panes
col1, col2, col3 = st.columns([1,2,1])
with col1:
    st.subheader("Queue")
    sel = st.selectbox("Select Alert ID", df['id'].tolist())
with col2:
    alert = next(a for a in get_alerts() if a['id']==sel)
    st.subheader(f"Details: {alert['id']}")
    st.markdown(f"**Title:** {alert['title']}")
    st.markdown(f"**Host:** {alert['host']}  **Status:** {alert['status']}")
    st.markdown(f"**Severity:** {alert['severity']}  **Time:** {alert['timestamp']}")
    ioc_str = ', '.join(alert['iocs'])
    st.markdown(f"**IOCs:** {ioc_str}")
    # Tabs
    tabs = st.tabs(["Summary","Process Tree","Operations"])
    with tabs[0]:
        st.write(alert.get('description',''))
        if st.button("AI Summary", key=sel+'_sum'):
            st.write(ask_ai(f"Summarize with actions: {alert}"))
    with tabs[1]:
        st.table(pd.DataFrame(alert['process_tree']))
    with tabs[2]:
        o_tabs = st.tabs(["Network","Disk","Registry"])
        for i, op in enumerate(['network','disk','registry']):
            data = alert['operations'].get(op, [])
            with o_tabs[i]:
                if data:
                    st.table(pd.DataFrame(data))
                else:
                    st.write("No records")
with col3:
    st.subheader("AI Assistant")
    if st.button("Suggest Actions", key=sel+'_act'):
        st.markdown(ask_ai(f"Given alert: {alert}, suggest 3 immediate SOC response steps."))
    if st.button("Explain IOCs/TTPs", key=sel+'_exp'):
        st.markdown(ask_ai(f"Explain significance of IOCs and technique {alert['technique']} for alert {alert['id']}"))
    query = st.text_input("Ask AI about this alert:", key=sel+'_qry')
    if st.button("Submit", key=sel+'_qry_btn') and query:
        st.write(ask_ai(query))
