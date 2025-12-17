#!/usr/bin/env python3
"""
ML Model Training for Network Anomaly Detection
Trains multiple models and selects best performer
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.neighbors import LocalOutlierFactor
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report, roc_auc_score
)
import joblib
import matplotlib.pyplot as plt
import seaborn as sns
import time


class AnomalyDetectionTrainer:
    """
    Trains and evaluates anomaly detection models
    Supports both supervised and unsupervised approaches
    """

    def __init__(self):
        self.models = {}
        self.results = {}
        self.best_model = None
        self.best_model_name = None

    def load_data(self):
        """Load preprocessed training data"""
        print("Loading training data...")

        try:
            self.X_train = np.load('X_train.npy')
            self.X_val = np.load('X_val.npy')
            self.X_test = np.load('X_test.npy')
            self.y_train = np.load('y_train.npy')
            self.y_val = np.load('y_val.npy')
            self.y_test = np.load('y_test.npy')

            print(f"Train set: {self.X_train.shape}")
            print(f"Validation set: {self.X_val.shape}")
            print(f"Test set: {self.X_test.shape}")

            return True
        except FileNotFoundError as e:
            print(f"Error: {e}")
            print("Run data_preprocessor.py first!")
            return False

    def train_random_forest(self):
        """Train Random Forest Classifier (Supervised)"""
        print("\n[1/4] Training Random Forest...")

        start_time = time.time()

        rf = RandomForestClassifier(
            n_estimators=100,
            max_depth=20,
            min_samples_split=10,
            min_samples_leaf=5,
            random_state=42,
            n_jobs=-1,
            verbose=0
        )

        rf.fit(self.X_train, self.y_train)
        train_time = time.time() - start_time

        y_pred = rf.predict(self.X_test)
        y_pred_proba = rf.predict_proba(self.X_test)[:, 1]

        self.models['RandomForest'] = rf
        self.results['RandomForest'] = {
            'accuracy': accuracy_score(self.y_test, y_pred),
            'precision': precision_score(self.y_test, y_pred),
            'recall': recall_score(self.y_test, y_pred),
            'f1_score': f1_score(self.y_test, y_pred),
            'roc_auc': roc_auc_score(self.y_test, y_pred_proba),
            'train_time': train_time,
            'confusion_matrix': confusion_matrix(self.y_test, y_pred)
        }

        print(f"  Accuracy: {self.results['RandomForest']['accuracy']:.4f}")
        print(f"  F1 Score: {self.results['RandomForest']['f1_score']:.4f}")
        print(f"  Training time: {train_time:.2f}s")

    def train_isolation_forest(self):
        """Train Isolation Forest (Unsupervised)"""
        print("\n[2/4] Training Isolation Forest...")

        start_time = time.time()

        X_benign = self.X_train[self.y_train == 0]

        iso_forest = IsolationForest(
            n_estimators=100,
            contamination=0.1,
            max_samples='auto',
            random_state=42,
            n_jobs=-1,
            verbose=0
        )

        iso_forest.fit(X_benign)
        train_time = time.time() - start_time

        y_pred_raw = iso_forest.predict(self.X_test)
        y_pred = np.where(y_pred_raw == 1, 0, 1)

        scores = iso_forest.decision_function(self.X_test)

        self.models['IsolationForest'] = iso_forest
        self.results['IsolationForest'] = {
            'accuracy': accuracy_score(self.y_test, y_pred),
            'precision': precision_score(self.y_test, y_pred),
            'recall': recall_score(self.y_test, y_pred),
            'f1_score': f1_score(self.y_test, y_pred),
            'train_time': train_time,
            'confusion_matrix': confusion_matrix(self.y_test, y_pred)
        }

        print(f"  Accuracy: {self.results['IsolationForest']['accuracy']:.4f}")
        print(f"  F1 Score: {self.results['IsolationForest']['f1_score']:.4f}")
        print(f"  Training time: {train_time:.2f}s")

    def train_one_class_svm(self):
        """Train One-Class SVM (Unsupervised)"""
        print("\n[3/4] Training One-Class SVM...")

        start_time = time.time()

        X_benign = self.X_train[self.y_train == 0]

        if len(X_benign) > 5000:
            indices = np.random.choice(len(X_benign), 5000, replace=False)
            X_benign = X_benign[indices]
            print(f"  Using subset of {len(X_benign)} samples for training")

        ocsvm = OneClassSVM(
            kernel='rbf',
            gamma='auto',
            nu=0.1,
            verbose=False
        )

        ocsvm.fit(X_benign)
        train_time = time.time() - start_time

        y_pred_raw = ocsvm.predict(self.X_test)
        y_pred = np.where(y_pred_raw == 1, 0, 1)

        self.models['OneClassSVM'] = ocsvm
        self.results['OneClassSVM'] = {
            'accuracy': accuracy_score(self.y_test, y_pred),
            'precision': precision_score(self.y_test, y_pred),
            'recall': recall_score(self.y_test, y_pred),
            'f1_score': f1_score(self.y_test, y_pred),
            'train_time': train_time,
            'confusion_matrix': confusion_matrix(self.y_test, y_pred)
        }

        print(f"  Accuracy: {self.results['OneClassSVM']['accuracy']:.4f}")
        print(f"  F1 Score: {self.results['OneClassSVM']['f1_score']:.4f}")
        print(f"  Training time: {train_time:.2f}s")

    def train_lof(self):
        """Train Local Outlier Factor (Unsupervised)"""
        print("\n[4/4] Training Local Outlier Factor...")

        start_time = time.time()

        lof = LocalOutlierFactor(
            n_neighbors=20,
            contamination=0.1,
            novelty=True
        )

        X_benign = self.X_train[self.y_train == 0]
        lof.fit(X_benign)
        train_time = time.time() - start_time

        y_pred_raw = lof.predict(self.X_test)
        y_pred = np.where(y_pred_raw == 1, 0, 1)

        self.models['LOF'] = lof
        self.results['LOF'] = {
            'accuracy': accuracy_score(self.y_test, y_pred),
            'precision': precision_score(self.y_test, y_pred),
            'recall': recall_score(self.y_test, y_pred),
            'f1_score': f1_score(self.y_test, y_pred),
            'train_time': train_time,
            'confusion_matrix': confusion_matrix(self.y_test, y_pred)
        }

        print(f"  Accuracy: {self.results['LOF']['accuracy']:.4f}")
        print(f"  F1 Score: {self.results['LOF']['f1_score']:.4f}")
        print(f"  Training time: {train_time:.2f}s")

    def compare_models(self):
        """Compare all trained models and select best"""
        print("\n" + "=" * 70)
        print("MODEL COMPARISON")
        print("=" * 70)

        comparison = pd.DataFrame(self.results).T
        comparison = comparison[['accuracy', 'precision', 'recall', 'f1_score', 'train_time']]

        print("\n", comparison.to_string())

        best_f1 = 0
        for name, metrics in self.results.items():
            if metrics['f1_score'] > best_f1:
                best_f1 = metrics['f1_score']
                self.best_model_name = name
                self.best_model = self.models[name]

        print(f"\n Best Model: {self.best_model_name} (F1={best_f1:.4f})")

        joblib.dump(self.best_model, 'best_model.pkl')
        with open('best_model_name.txt', 'w') as f:
            f.write(self.best_model_name)
        print("Best model saved to best_model.pkl")

    def plot_confusion_matrices(self):
        """Plot confusion matrices for all models"""
        print("\nGenerating confusion matrix plots...")

        fig, axes = plt.subplots(2, 2, figsize=(12, 10))
        fig.suptitle('Confusion Matrices for All Models', fontsize=16)

        for idx, (name, metrics) in enumerate(self.results.items()):
            row = idx // 2
            col = idx % 2
            cm = metrics['confusion_matrix']

            sns.heatmap(
                cm,
                annot=True,
                fmt='d',
                cmap='Blues',
                ax=axes[row, col],
                xticklabels=['Benign', 'Attack'],
                yticklabels=['Benign', 'Attack']
            )

            axes[row, col].set_title(f'{name}\nF1={metrics["f1_score"]:.3f}')
            axes[row, col].set_xlabel('Predicted')
            axes[row, col].set_ylabel('Actual')

        plt.tight_layout()
        plt.savefig('confusion_matrices.png', dpi=300, bbox_inches='tight')
        plt.close()
        print("Confusion matrices saved to confusion_matrices.png")

    def plot_per_model_metrics(self):
        """
        Create one bar chart per model:
        x-axis = metrics, y-axis = values.
        """
        print("Generating per-model metric plots...")

        metrics_to_plot = ['accuracy', 'precision', 'recall', 'f1_score']
        for name, res in self.results.items():
            values = [res[m] for m in metrics_to_plot]

            plt.figure(figsize=(6, 4))
            plt.bar(metrics_to_plot, values,
                    color=['steelblue', 'seagreen', 'orange', 'crimson'])
            plt.ylim(0, 1.05)
            plt.ylabel('Score')
            plt.title(f'{name} Performance Metrics')
            plt.grid(axis='y', linestyle='--', alpha=0.4)
            plt.tight_layout()

            filename = f'{name.lower()}_metrics.png'
            plt.savefig(filename, dpi=300, bbox_inches='tight')
            plt.close()
            print(f"Per-model metrics saved to {filename}")

    def plot_metric_comparison(self):
        """
        Overall comparison graph:
        grouped bar chart with all four models on x-axis
        and accuracy/precision/recall/F1 as grouped bars.
        Also a separate training-time bar chart.
        """
        print("Generating overall comparison plots...")

        comparison = pd.DataFrame(self.results).T[
            ['accuracy', 'precision', 'recall', 'f1_score', 'train_time']
        ]

        models = comparison.index.tolist()
        metrics_to_plot = ['accuracy', 'precision', 'recall', 'f1_score']

        x = np.arange(len(models))
        width = 0.18

        # Grouped bar chart for main metrics
        plt.figure(figsize=(10, 6))
        for i, m in enumerate(metrics_to_plot):
            plt.bar(
                x + i * width,
                comparison[m].values,
                width=width,
                label=m.capitalize()
            )

        plt.xticks(x + width * (len(metrics_to_plot) - 1) / 2, models)
        plt.ylim(0, 1.05)
        plt.ylabel('Score')
        plt.title('Overall Model Performance Comparison')
        plt.legend()
        plt.grid(axis='y', linestyle='--', alpha=0.4)
        plt.tight_layout()
        plt.savefig('model_metrics_comparison.png', dpi=300, bbox_inches='tight')
        plt.close()

        # Training time comparison
        plt.figure(figsize=(8, 5))
        plt.bar(models, comparison['train_time'].values, color='purple')
        plt.ylabel('Training time (s)')
        plt.title('Training Time for Each Model')
        plt.grid(axis='y', linestyle='--', alpha=0.4)
        plt.tight_layout()
        plt.savefig('model_train_time.png', dpi=300, bbox_inches='tight')
        plt.close()

        print("Overall comparison plots saved as model_metrics_comparison.png and model_train_time.png")

    def train_all_models(self):
        """Train all models"""
        if not self.load_data():
            return False

        print("\n" + "=" * 70)
        print("TRAINING ANOMALY DETECTION MODELS")
        print("=" * 70)

        self.train_random_forest()
        self.train_isolation_forest()
        self.train_one_class_svm()
        self.train_lof()

        self.compare_models()
        self.plot_confusion_matrices()
        self.plot_per_model_metrics()
        self.plot_metric_comparison()

        print("\n=== TRAINING COMPLETE ===")
        return True


def main():
    trainer = AnomalyDetectionTrainer()
    trainer.train_all_models()


if __name__ == '__main__':
    main()
