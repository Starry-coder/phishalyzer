from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
import joblib

class EmailClassifier:
    def __init__(self, n_estimators: int = 200, random_state: int = 42):
        self.model = RandomForestClassifier(n_estimators=n_estimators, random_state=random_state)
        self._trained = False

    def train(self, X, y):
        self.model.fit(X, y)
        self._trained = True

    def predict(self, X):
        return self.model.predict(X)

    def predict_proba(self, X):
        if hasattr(self.model, "predict_proba"):
            return self.model.predict_proba(X)
        # Fallback: uniform probabilities if not supported
        import numpy as np
        preds = self.model.predict(X)
        # Assume binary classes {0,1}
        probs = np.column_stack([1 - preds, preds])
        return probs

    def is_trained(self) -> bool:
        return bool(self._trained)

    def save_model(self, filepath):
        joblib.dump(self.model, filepath)

    def load_model(self, filepath):
        self.model = joblib.load(filepath)
        self._trained = True

    def evaluate(self, X_test, y_test):
        predictions = self.predict(X_test)
        accuracy = accuracy_score(y_test, predictions)
        report = classification_report(y_test, predictions)
        return accuracy, report