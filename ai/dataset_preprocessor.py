#!/usr/bin/env python3
"""
Data Preprocessing Pipeline for Network Traffic ML
Cleans, normalizes, and prepares data for training
"""

import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
import joblib
import sys


class NetworkDataPreprocessor:
    """
    Preprocesses network flow data for ML training
    Handles missing values, encoding, normalization
    """
    def __init__(self, input_file='training_dataset.csv'):
        self.input_file = input_file
        self.df = None
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()

        # Internal feature names (after renaming)
        self.feature_columns = [
            'duration_sec',
            'packets_total',
            'bytes_total',
            'packets_per_sec',
            'bytes_per_sec',
            'avg_packet_size',
            'src_port',
            'dst_port'
        ]

    def load_data(self):
        """Load CSV data and rename CIC-IDS2017 columns."""
        print(f"Loading data from {self.input_file}...")
        try:
            self.df = pd.read_csv(self.input_file)
            print(f"Loaded {len(self.df)} samples")
            print(f"Columns: {list(self.df.columns)}")

            # Map CIC-IDS2017 original column names to internal names
            rename_map = {
                'Flow Duration': 'duration_sec',
                'Total Fwd Packets': 'packets_total',
                # You can add Total Backward Packets into packets_total later if needed
                'Total Length of Fwd Packets': 'bytes_total',
                'Destination Port': 'dst_port',
                'Source Port': 'src_port',
                'Flow Bytes/s': 'bytes_per_sec',
                'Flow Packets/s': 'packets_per_sec',
                'Average Packet Size': 'avg_packet_size'
            }
            self.df = self.df.rename(columns=rename_map)

            return True
        except FileNotFoundError:
            print(f"Error: File {self.input_file} not found")
            return False
        except Exception as e:
            print(f"Error loading data: {e}")
            return False

    def clean_data(self):
        """Clean and handle missing values"""
        print("\nCleaning data...")

        # CIC-IDS2017 label column (note leading space)
        label_col = ' Label'

        if label_col not in self.df.columns:
            print("Label column not found. Available columns:")
            print(self.df.columns.tolist())
            raise SystemExit(1)

        initial_count = len(self.df)
        self.df = self.df.dropna(subset=[label_col])

        # Ensure all feature columns exist before numeric conversion
        for col in self.feature_columns:
            if col not in self.df.columns:
                # If a feature is missing, create it as 0
                self.df[col] = 0

        # Convert feature columns to numeric
        for col in self.feature_columns:
            self.df[col] = pd.to_numeric(self.df[col], errors='coerce')

        # Fill missing numeric values with 0
        self.df[self.feature_columns] = self.df[self.feature_columns].fillna(0)

        # Remove infinite values and duplicates
        self.df = self.df.replace([np.inf, -np.inf], 0)
        self.df = self.df.drop_duplicates()

        final_count = len(self.df)
        print(f"Removed {initial_count - final_count} invalid samples")
        print(f"Final dataset size: {final_count}")

    def encode_labels(self):
        """Encode string labels to numeric"""
        print("\nEncoding labels...")

        label_col = ' Label'

        print(f"Original labels: {self.df[label_col].unique()}")

        # Binary classification: BENIGN vs attack
        self.df['label_binary'] = self.df[label_col].apply(
            lambda x: 0 if x == 'BENIGN' else 1
        )

        # Multi-class classification
        self.df['label_encoded'] = self.label_encoder.fit_transform(self.df[label_col])

        print("Label mapping:")
        for i, label in enumerate(self.label_encoder.classes_):
            print(f"  {i}: {label}")

        joblib.dump(self.label_encoder, 'label_encoder.pkl')
        print("Label encoder saved to label_encoder.pkl")

    def normalize_features(self):
        """Normalize numeric features"""
        print("\nNormalizing features...")
        X = self.df[self.feature_columns].values
        X_normalized = self.scaler.fit_transform(X)
        for i, col in enumerate(self.feature_columns):
            self.df[f'{col}_normalized'] = X_normalized[:, i]
        joblib.dump(self.scaler, 'feature_scaler.pkl')
        print("Feature scaler saved to feature_scaler.pkl")

    def engineer_features(self):
        """Create additional derived features"""
        print("\nEngineering additional features...")
        self.df['bytes_per_packet'] = np.where(
            self.df['packets_total'] > 0,
            self.df['bytes_total'] / self.df['packets_total'],
            0
        )
        self.df['traffic_intensity'] = np.where(
            self.df['duration_sec'] > 0,
            (self.df['packets_total'] * self.df['bytes_total']) / self.df['duration_sec'],
            0
        )
        self.df['is_common_port'] = self.df['dst_port'].apply(
            lambda x: 1 if x in [80, 443, 22, 21, 25, 53] else 0
        )

        self.feature_columns.extend([
            'bytes_per_packet',
            'traffic_intensity',
            'is_common_port'
        ])
        print(f"Total features: {len(self.feature_columns)}")

    def split_data(self, test_size=0.2, val_size=0.1):
        """Split into train/val/test and save .npy files"""
        print(f"\nSplitting data (train/val/test = {1-test_size-val_size}/{val_size}/{test_size})...")

        feature_cols_norm = [
            f'{col}_normalized' for col in self.feature_columns
            if f'{col}_normalized' in self.df.columns
        ]

        X = self.df[feature_cols_norm].values
        y_binary = self.df['label_binary'].values
        y_multi = self.df['label_encoded'].values  # kept if you need multi-class later

        X_temp, X_test, y_temp, y_test = train_test_split(
            X, y_binary, test_size=test_size, random_state=42, stratify=y_binary
        )

        val_relative_size = val_size / (1 - test_size)
        X_train, X_val, y_train, y_val = train_test_split(
            X_temp, y_temp, test_size=val_relative_size, random_state=42, stratify=y_temp
        )

        print(f"Train set: {len(X_train)} samples")
        print(f"Validation set: {len(X_val)} samples")
        print(f"Test set: {len(X_test)} samples")

        np.save('X_train.npy', X_train)
        np.save('X_val.npy', X_val)
        np.save('X_test.npy', X_test)
        np.save('y_train.npy', y_train)
        np.save('y_val.npy', y_val)
        np.save('y_test.npy', y_test)

        print("\nDatasets saved:")
        print("  X_train.npy, y_train.npy")
        print("  X_val.npy, y_val.npy")
        print("  X_test.npy, y_test.npy")

        return X_train, X_val, X_test, y_train, y_val, y_test

    def generate_statistics(self):
        """Print basic stats and save processed CSV"""
        print("\n=== Dataset Statistics ===")
        print("\nLabel Distribution:")
        print(self.df[' Label'].value_counts())
        print("\nFeature Statistics:")
        print(self.df[self.feature_columns].describe())

        output_file = 'processed_dataset.csv'
        self.df.to_csv(output_file, index=False)
        print(f"\nProcessed dataset saved to {output_file}")

    def process_pipeline(self):
        """Run full preprocessing pipeline"""
        if not self.load_data():
            return False
        self.clean_data()
        self.encode_labels()
        self.engineer_features()
        self.normalize_features()
        self.split_data()
        self.generate_statistics()
        print("\n=== PREPROCESSING COMPLETE ===")
        return True


def main():
    if len(sys.argv) > 1:
        input_file = sys.argv[1]
    else:
        input_file = 'training_dataset.csv'

    preprocessor = NetworkDataPreprocessor(input_file)
    preprocessor.process_pipeline()


if __name__ == '__main__':
    main()
