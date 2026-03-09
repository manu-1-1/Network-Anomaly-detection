---
description: Common workflows for the Network Anomaly Detection project
---

# Network Anomaly Detection — Common Workflows

## 1. Run the CLI Risk Scorer (Live Network Analysis)

```powershell
cd d:\Network-Anomaly-detection
python cli_risk_scorer.py
```

## 2. Run CLI Risk Scorer with Verbose Output

```powershell
cd d:\Network-Anomaly-detection
python cli_risk_scorer.py --verbose
```

## 3. Launch Jupyter Notebook (for model training / exploration)

```powershell
cd d:\Network-Anomaly-detection
jupyter notebook
```

Then open any of the following notebooks in the browser:
- `Model.ipynb` — Main model training notebook
- `Random_forestipynb` — Random Forest classifier
- `Randomforest_feature_selection.ipynb` — RF with feature selection
- `Decision_tree.ipynb` — Decision Tree classifier
- `Logistic_with_l1_feature_Selection.ipynb` — Logistic Regression with L1
- `svm_rbf.ipynb` — SVM with RBF kernel

## 4. Install Dependencies

```powershell
cd d:\Network-Anomaly-detection
pip install -r requirements.txt
```

If no `requirements.txt` exists, install the core packages manually:

```powershell
pip install scikit-learn pandas numpy joblib psutil scapy
```

## 5. Load a Saved Model in Python (copy-paste snippet)

```python
import joblib

# Choose the model you want:
model = joblib.load("random_forest_ids_model.joblib")
# model = joblib.load("rf_ids_model_with_feature_selection.joblib")
# model = joblib.load("decision_tree_ids_model.joblib")
# model = joblib.load("logistic_l1_ids_model.joblib")

print("Model loaded:", model)
```

## 6. Dataset Location

```
d:\Network-Anomaly-detection\Datasets\
```

Load a dataset in a notebook:

```python
import pandas as pd

df = pd.read_csv("Datasets/<your_dataset_file>.csv")
print(df.shape)
df.head()
```

## 7. Quick Prediction Snippet (copy-paste)

```python
import joblib
import pandas as pd

model = joblib.load("random_forest_ids_model.joblib")

# Replace with actual feature values
sample = pd.DataFrame([{
    "feature1": 0,
    "feature2": 0,
    # ... add all required features
}])

prediction = model.predict(sample)
print("Prediction:", prediction)
```

## 8. Check Model Feature Importances (Random Forest)

```python
import joblib
import pandas as pd

model = joblib.load("random_forest_ids_model.joblib")
importances = pd.Series(model.feature_importances_).sort_values(ascending=False)
print(importances.head(20))
```
