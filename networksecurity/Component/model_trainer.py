import os
import sys

from networksecurity.exception.exception import NetworkSecurityException 
from networksecurity.logging.logger import logging

from networksecurity.entity.artifact_entity import DataTransformationArtifact, ModelTrainerArtifact
from networksecurity.entity.config_entity import ModelTrainerConfig

from networksecurity.utils.ml_utils.model.estimator import NetworkModel
from networksecurity.utils.main_utils.utils import save_object, load_object
from networksecurity.utils.main_utils.utils import load_numpy_array_data, evaluate_models
from networksecurity.utils.ml_utils.metric.classification_metric import get_classification_score

from sklearn.linear_model import LogisticRegression
from sklearn.neighbors import KNeighborsClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import AdaBoostClassifier, GradientBoostingClassifier, RandomForestClassifier
import mlflow
from urllib.parse import urlparse

import dagshub

dagshub.init(repo_owner='luckyl2829893', repo_name='networksecurity', mlflow=True)

os.environ["MLFLOW_TRACKING_URI"] = "https://dagshub.com/luckyl2829893/networksecurity.mlflow"
os.environ["MLFLOW_TRACKING_USERNAME"] = "luckyl2829893"
os.environ["MLFLOW_TRACKING_PASSWORD"] = "af648c8d94618f713b93b227b717b9bedaa6aabf"


class ModelTrainer:
    def __init__(self, model_trainer_config: ModelTrainerConfig, data_transformation_artifact: DataTransformationArtifact):
        print("Debug : model trainer __init__ called")
        try:
            self.model_trainer_config = model_trainer_config
            self.data_transformation_artifact = data_transformation_artifact
        except Exception as e:
            raise NetworkSecurityException(e, sys)

    def track_mlflow(self, best_model, classificationmetric):
        print("Debug : track_mlflow method entered")
        with mlflow.start_run():
            mlflow.log_metric("f1_score", classificationmetric.f1_score)
            mlflow.log_metric("precision", classificationmetric.precision_score)
            mlflow.log_metric("recall_score", classificationmetric.recall_score)
        # Use name param to avoid deprecated warning
            print("calling mlflow.sklearn.log_model without registry ")
            mlflow.sklearn.log_model(best_model,"model")


    def train_model(self, X_train, y_train, x_test, y_test):
        print("DEBUG :  self  train test " )
        models = {
            "Random Forest": RandomForestClassifier(verbose=1),
            "Decision Tree": DecisionTreeClassifier(),
            "Gradient Boosting": GradientBoostingClassifier(verbose=1),
            "Logistic Regression": LogisticRegression(verbose=1),
            "AdaBoost": AdaBoostClassifier(),
        }
        params = {
            "Decision Tree": {
                'criterion': ['gini', 'entropy', 'log_loss'],
            },
            "Random Forest": {
                'n_estimators': [8, 16, 32, 128, 256]
            },
            "Gradient Boosting": {
                'learning_rate': [.1, .01, .05, .001],
                'subsample': [0.6, 0.7, 0.75, 0.85, 0.9],
                'n_estimators': [8, 16, 32, 64, 128, 256]
            },
            "Logistic Regression": {},
            "AdaBoost": {
                'learning_rate': [.1, .01, .001],
                'n_estimators': [8, 16, 32, 64, 128, 256]
            }
        }
        model_report: dict = evaluate_models(
            X_train=X_train, y_train=y_train, X_test=x_test, y_test=y_test,
            models=models, param=params
        )

        ## To get best model score from dict by F1 score
        best_model_score = max(metrics["f1"] for metrics in model_report.values())

        ## To get best model name from dict
        best_model_name = [
            name for name, metrics in model_report.items() if metrics["f1"] == best_model_score
        ][0]

        best_model = models[best_model_name]
        y_train_pred = best_model.predict(X_train)

        classification_train_metric = get_classification_score(y_true=y_train, y_pred=y_train_pred)

        ## Track the experiments with mlflow
        self.track_mlflow(best_model, classification_train_metric)

        y_test_pred = best_model.predict(x_test)
        classification_test_metric = get_classification_score(y_true=y_test, y_pred=y_test_pred)

        self.track_mlflow(best_model, classification_test_metric)

        preprocessor = load_object(file_path=self.data_transformation_artifact.transformed_object_file_path)

        model_dir_path = os.path.dirname(self.model_trainer_config.trained_model_file_path)
        os.makedirs(model_dir_path, exist_ok=True)

        Network_Model = NetworkModel(preprocessor=preprocessor, model=best_model)
        save_object(self.model_trainer_config.trained_model_file_path, obj=Network_Model)
        # model pusher
        save_object("final_model/model.pkl", best_model)

        ## Model Trainer Artifact
        model_trainer_artifact = ModelTrainerArtifact(
            trained_model_file_path=self.model_trainer_config.trained_model_file_path,
            train_metric_artifact=classification_train_metric,
            test_metric_artifact=classification_test_metric
        )
        logging.info(f"Model trainer artifact: {model_trainer_artifact}")
        return model_trainer_artifact

    def initiate_model_trainer(self) -> ModelTrainerArtifact:
        print("DEBUG : initiate model_trainer")
        try:
            train_file_path = self.data_transformation_artifact.transformed_train_file_path
            test_file_path = self.data_transformation_artifact.transformed_test_file_path

            # loading training array and testing array
            train_arr = load_numpy_array_data(train_file_path)
            test_arr = load_numpy_array_data(test_file_path)

            x_train, y_train, x_test, y_test = (
                train_arr[:, :-1],
                train_arr[:, -1],
                test_arr[:, :-1],
                test_arr[:, -1],
            )

            model_trainer_artifact = self.train_model(x_train, y_train, x_test, y_test)
            return model_trainer_artifact

        except Exception as e:
            raise NetworkSecurityException(e, sys)
if __name__ == "__main__":
    print("DEBUG: Entered model_trainer.py main block")
    # You need to construct objects with dummy or test arguments here
    # For example, create a ModelTrainer instance and call a method
    # If your config and artifact classes require files, mock or dummy them for this test
    # Example (adjust as needed for your context):
    # dummy_config = ModelTrainerConfig(...)
    # dummy_artifact = DataTransformationArtifact(...)
    # trainer = ModelTrainer(dummy_config, dummy_artifact)
    # trainer.initiate_model_trainer()

    print("DEBUG: Finished model_trainer.py main block")