## AI-Driven Software-Defined Networking for Automated Threat Response
### AI-powered Software-Defined Networking (SDN) project that detects anomalous traffic using machine learning and automatically enforces mitigation actions through an SDN controller and Mininet testbed. This repository currently implements up to Phase 4 of the full architecture (AI models + Flask API + Ryu controller + Mininet integration).​

### Features (Up to Phase 4)
- Flow-based feature extraction from Mininet / pcap datasets.​

- Multiple ML models for anomaly / attack detection (e.g., Random Forest, Isolation Forest, One-Class SVM, Local Outlier Factor).​

- RESTful Flask API to expose trained AI models for real-time predictions.​

- Ryu SDN controller that:

  - Collects flow statistics from OpenFlow switches.

  - Sends features to the AI API.

  - Automatically installs mitigation rules (block/quarantine flows, micro-segmentation) when an attack is detected.​

- Mininet topology to emulate attackers, victims, and normal clients for testing.​

- Basic dashboard/graphs (static or generated images) to visualize model performance and detection metrics.​

### Repository Structure
Adapt this section to your actual repo layout, but a typical structure is:

`text`
```

.
├── ai_api/                 # Flask AI service (Phase 2–3)
│   ├── app.py              # Main Flask app exposing /predict
│   ├── models/             # Saved ML models (pickle/joblib)
│   ├── preprocessing/      # Feature engineering / scaling code
│   └── requirements.txt
├── controller/             # Ryu SDN controller (Phase 3–4)
│   ├── microseg_controller.py   # Flow collection + mitigation logic
│   └── requirements.txt
├── mininet/                # Mininet testbed & traffic generation
│   ├── topo.py             # Custom topology script
│   ├── flow_collector.py   # PCAP/flow exporter scripts
│   └── traffic_scripts/    # hping3/nmap/iperf attack generators
├── notebooks/              # Model training & evaluation (Phase 2)
│   └── *.ipynb
├── data/                   # Datasets (e.g., CICIDS + custom flows)
│   └── processed/          # Feature-engineered CSVs
├── images/                 # Metrics graphs, confusion matrices, etc.
└── README.md

```

### Prerequisites
- OS: Ubuntu 20.04+

- Python: 3.8+

- Tools:

  - Mininet

  - Ryu SDN framework

  - scikit-learn, pandas, numpy, matplotlib, seaborn

  - Flask / requests

Example installation (adjust to your environment):

`bash`
```

sudo apt-get update
sudo apt-get install -y git python3 python3-pip

# Mininet (if not already installed)
sudo apt-get install -y mininet

# Ryu
pip3 install ryu

# Project requirements
pip3 install -r ai_api/requirements.txt
pip3 install -r controller/requirements.txt
```
### How It Works (Phases 1–4)
#### Phase 1: Problem Definition & Dataset
- Identifies limitations of traditional static network security against dynamic threats like DDoS, ransomware, APTs.​

- Uses public datasets (e.g., CICIDS) plus custom traffic captured from Mininet (normal + attack scenarios).​

#### Phase 2: Model Training
- Preprocesses network flow features (normalization, encoding, feature selection).​

- Trains and compares multiple models:

  - Random Forest (primary detector)

  - Isolation Forest

  - Local Outlier Factor

  - One-Class SVM

- Evaluates using accuracy, precision, recall, F1-score, ROC-AUC and confusion matrices; best-performing model is exported for inference.​

#### Phase 3: AI API Service
- Wraps the trained model(s) in a Flask API (`app.py`).​

- Exposes endpoints such as:

  - `POST /predict` – accepts JSON payload of flow features and returns `NORMAL` / `ATTACK` predictions and probability/score.​

  - Handles preprocessing at inference time (same pipeline as in training).​

#### Phase 4: SDN Integration (Ryu + Mininet)
- Runs a custom Ryu controller (`microseg_controller.py`) that:

  - Builds a Mininet topology (or connects to an existing one).​

  - Periodically polls flow stats from OpenFlow switches.

  - Sends aggregated flow features to the Flask AI API.

  - Interprets the model output and:

    - Installs blocking rules (drop flows from suspected attacker hosts).

    - Moves hosts into restricted zones (micro-segmentation).

    - Logs events for later analysis.​

- Mininet scripts generate:

  - Normal web/SSH/ICMP traffic.

  - Attack traffic (SYN flood, UDP flood, port scans, brute-force, etc.) to validate detection and automated response.​

### Quick Start
#### 1. Clone the repository

`bash`
```
git clone https://github.com/<your-username>/<your-repo>.git
cd <your-repo>
```
#### 2. Start the AI API

`bash`
```
cd ai_api
pip3 install -r requirements.txt
python3 app.py    # Usually runs on http://127.0.0.1:5000
```

#### 3. Run the Ryu controller
`bash`
```
cd controller
ryu-manager microseg_controller.py
Launch Mininet topology
```

#### 4. In a new terminal:
`bash`
```
cd mininet
sudo python3 topo.py
```

#### 5. Generate test traffic

From Mininet CLI or helper scripts, run:

- Normal traffic: `iperf`, `ping` between hosts

- Attack traffic: `hping3`, `nmap`, custom scripts under `traffic_scripts/`

Observe:

- AI API logs predictions.

- Ryu installs mitigation flows (quarantine/block rules).

- Host connectivity changes according to threat classification.​

### Current Status and Roadmap
- ✅ Phase 1–4 implemented (dataset, models, AI API, Ryu integration, Mininet testbed).​

- 🔄 Under development:

  - NFV integration with pfSense + Suricata as VNFs.

  - NFV orchestrator and full service chaining.

  - Blockchain-based trust and XAI explanations as future upgrade phases.​
