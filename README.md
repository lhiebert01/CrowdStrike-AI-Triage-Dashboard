# CrowdStrike Enhanced EDR Dashboard

## Enabling Faster, Better, Smarter Endpoint Security, Triage and Effective Response

**Designed by: [Lindsay Hiebert](https://www.linkedin.com/in/lindsayhiebert/)**

![CrowdStrike Shield](https://raw.githubusercontent.com/lhiebert01/CrowdStrike-AI-Triage-Dashboard/main/assets/cs-shield.png)

This project demonstrates an AI-powered enhancement to CrowdStrike's Endpoint Detection and Response (EDR) platform. The dashboard helps SOC analysts work more efficiently by providing contextual information, AI assistance, and streamlined workflows for triaging security alerts.

## 🛡️ Overview

This Streamlit application showcases how multiple AI models (Google Gemini and OpenAI) can be integrated with security operations center (SOC) workflows to improve analyst efficiency and effectiveness. The application features:

- **AI-Enhanced Triage Dashboard**: Intelligent grouping and filtering of alerts with AI-powered analysis
- **Dual AI Model Integration**: Fallback capability between Google Gemini and OpenAI models for reliability
- **Security-Centric AI Assistant**: Contextual help with high-priority threat information
- **SOC Analyst Knowledge Base**: Quick access to common security workflows and documentation

## ✨ Key Features

### Triage Dashboard

- **Dynamic Alert Filtering**: Filter by severity, host, technique, and free-text search
- **Smart Alert Grouping**: Group related alerts by host, technique, or other criteria
- **Expandable Alert Details**: Tabbed interface showing summary, process tree, and operations
- **AI-Powered Analysis**: Get concise or detailed AI analysis of alerts with a single click

### AI Assistant

- **Security-Focused Interface**: Branded UI with CrowdStrike styling and security context
- **High-Priority Threat Examples**: Quick access to common threat scenarios and responses
- **Concise & Detailed Responses**: Default concise responses with option to expand for details
- **Conversation History Management**: Recent-first conversation display with download capability
- **Contextual Help Sections**: Pre-defined contexts for different security workflows

### Technical Capabilities

- **Dual AI Provider Support**: Seamless fallback between Google Gemini and OpenAI
- **Enhanced Error Handling**: Graceful degradation when API services are unavailable
- **Conversation Export**: Download conversations as markdown files
- **Empty Results Handling**: User-friendly messages when filters return no results

## 🚀 Getting Started

### Prerequisites

- Python 3.12.x
- Conda environment manager

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/lhiebert01/CrowdStrike-AI-Triage-Dashboard.git
   cd CrowdStrike-AI-Triage-Dashboard
   ```

2. Create and activate conda environment:
   ```bash
   conda create -p venv python=3.12.9 -y
   conda activate venv
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Create a `.env` file in the project root with your API keys:
   ```
   GOOGLE_API_KEY=your_gemini_api_key_here
   OPENAI_API_KEY=your_openai_api_key_here
   ```

5. Run the application:
   ```bash
   streamlit run app.py
   ```

## 📋 Usage Guide

### Triage Dashboard

1. **Filtering Alerts**:
   - Use the sidebar sliders to filter by severity
   - Select hosts and techniques from the multiselect dropdowns
   - Enter free text in the search box to find specific content

2. **Grouping Alerts**:
   - Select a grouping criterion from the dropdown (host, technique, etc.)
   - Expand any group to see its alerts and statistics
   - Use the "AI Summary" button for AI-generated analysis of the group

3. **Alert Details**:
   - Select an alert ID to view complete information
   - Navigate through tabs to see process tree and operations
   - Use AI buttons for suggested actions and explanations

### AI Assistant

1. **Asking Questions**:
   - Select "AI Chat" from the view mode radio buttons
   - Enter questions in the text area or use sample questions

2. **Using Contextual Help**:
   - Click on a context button (Alert Triage, Incident Response, etc.)
   - The AI will provide guidance specific to that security domain
   
3. **Exploring Threat Scenarios**:
   - Click on high-priority threats to get detailed information
   - Learn about APT groups, ransomware, credential theft, etc.

4. **Managing Conversations**:
   - View conversation history with newest messages first
   - Click "Show More Details" to expand concise responses
   - Download the entire conversation as a markdown file

## 🔒 Security Considerations

- This application is for demonstration purposes
- API keys are stored in a .env file excluded from version control
- In production, implement proper authentication and authorization
- Consider data privacy regulations when processing security data

## 📦 Project Structure

- `app.py`: Main application with triage dashboard and AI assistant
- `requirements.txt`: Python dependencies
- `.env`: API keys for AI services (not in version control)
- `README.md`: Project documentation
- `MEDIUM.md`: Detailed article about the project
- `LINKEDIN.md`: LinkedIn post content
- `assets/`: Images and screenshots for documentation

## 🔄 Deployment

This application is ready for deployment on Streamlit Cloud:

1. Visit [Streamlit Cloud](https://streamlit.io/cloud)
2. Connect to your GitHub repository (https://github.com/lhiebert01/CrowdStrike-AI-Triage-Dashboard)
3. Select `app.py` as the main file
4. Add the following secrets in the Streamlit dashboard:
   ```
   GOOGLE_API_KEY=your_gemini_api_key_here
   OPENAI_API_KEY=your_openai_api_key_here
   ```
5. Deploy the application

Alternatively, the application can be deployed on other platforms such as:
- **Render**: For simple web service hosting
- **Heroku**: For scalable application deployment

## 📝 License

This project is licensed under the MIT License.

## 🙏 Acknowledgments

- **[Lindsay Hiebert](https://www.linkedin.com/in/lindsayhiebert/)** - Design and development
- CrowdStrike for EDR platform inspiration
- Google for the Gemini AI platform
- OpenAI for their generative AI capabilities
- Streamlit for the application framework

## 📢 Feedback

I welcome your feedback and suggestions! Please connect with me on [LinkedIn](https://www.linkedin.com/in/lindsayhiebert/) to share your thoughts about this project.