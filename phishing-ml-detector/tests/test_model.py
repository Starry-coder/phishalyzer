import pytest
from src.ml.model import EmailClassifier
from src.ml.dataset import load_data
from sklearn.metrics import accuracy_score

@pytest.fixture
def sample_data():
    return load_data()

def test_model_training(sample_data):
    model = EmailClassifier()
    X_train, y_train = sample_data['features'], sample_data['labels']
    model.train(X_train, y_train)
    assert model.is_trained()

def test_model_prediction(sample_data):
    model = EmailClassifier()
    X_test, y_test = sample_data['features'], sample_data['labels']
    model.train(X_test, y_test)
    preds = model.predict(X_test)
    assert len(preds) == len(y_test)

def test_model_accuracy(sample_data):
    model = EmailClassifier()
    X_train, y_train = sample_data['features'], sample_data['labels']
    model.train(X_train, y_train)
    preds = model.predict(X_train)
    acc = accuracy_score(y_train, preds)
    assert acc >= 0.5  # synthetic data; keep threshold modest