# Network Anomaly Detection

This is a simple network intrusion detection system (IDS) built using machine learning. It captures live network traffic statistics and uses models trained on the UNSW-NB15 dataset to classify traffic as normal or potentially anomalous.

## How it works

The core script (`cli_risk_scorer.py`) uses `psutil` to sample active network connections and traffic flow. It extracts features that map to the UNSW-NB15 dataset and then passes them through a pre-trained model to get a threat probability score.

Risk levels:
- **0-24%**: Low Risk (looks normal)
- **25-49%**: Medium Risk (model is uncertain, but currently benign)
- **50-74%**: High Risk (anomaly detected)
- **75-100%**: Critical Risk (strong anomaly, worth investigating)

## Setup

First, install the required dependencies:

```bash
pip install joblib numpy pandas psutil scikit-learn rich
```

*Note: `rich` is just used for formatting the terminal output.*

## Usage

You can run the script located in the `src` folder.

**Interactive menu:**
```bash
python src/cli_risk_scorer.py
```

**Continuous monitoring (runs every 10 seconds):**
```bash
python src/cli_risk_scorer.py --model rf --watch
```

**Testing against the dataset:**
If you want to see how the model scores an actual malicious row from the dataset (rather than your current network traffic), you can use the sample flag:
```bash
python src/cli_risk_scorer.py --model rf --sample --detailed
```

## Available Models

We have a few different models to choose from, which you can specify using the `--model` argument:

- **Random Forest (`rf`)**: Recommended. It's an ensemble of trees and provides the most accurate results on the test set.
- **Decision Tree (`dt`)**: A single tree. It's fast and easy to interpret, but might overfit compared to the forest.
- **Ensemble (`ensemble`)**: A weighted average combining both the Random Forest and Decision Tree.

## Folder Structure

- `Datasets/`: Contains the UNSW-NB15 test set used for the `--sample` command.
- `models/`: The pre-trained `.joblib` models.
- `notebooks/`: Jupyter notebooks used for data exploration and model training.
- `src/`: Source code, including the main CLI script.

## About the Dataset

The models were trained on the UNSW-NB15 dataset from the Australian Centre for Cyber Security. It contains normal traffic along with 9 different attack families (like DoS, Fuzzing, Backdoor, etc.).
