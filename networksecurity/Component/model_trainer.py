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

# NOTE: Since you are setting the DagsHub URI in main.py, you can optionally remove 
# these lines if they are redundant, but keeping them here ensures ModelTrainer can 
# always log to DagsHub even if run independently.
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
        print("Debug : track_mlflow method entered. Logging to DagsHub.")
        
        # This run now correctly uses the remote DagsHub URI set in environment variables.
        with mlflow.start_run() as run:
            
            # 1. Log Metrics to DagsHub
            mlflow.log_metric("f1_score", classificationmetric.f1_score)
            mlflow.log_metric("precision", classificationmetric.precision_score)
            mlflow.log_metric("recall_score", classificationmetric.recall_score)
            
            # 2. Log Model Artifact to DagsHub
            # mlflow.sklearn.log_model handles saving the model locally, packaging it, 
            # and then uploading it to the remote DagsHub artifact storage.
            mlflow.sklearn.log_model(
                sk_model=best_model,
                artifact_path="model_artifact", # Artifact folder name on DagsHub
                # Use 'name' instead of 'artifact_path' to silence the deprecation warning
            )
            
            print(f"Metrics and Model logged to DagsHub Run ID: {run.info.run_id}")
            # NOTE:  original error is resolved because we are no longer trying to 
            # switching to a local URI mid-run, which caused the run ID mismatch.

    # --------------------------------------------------------------------


    def train_model(self, X_train, y_train, x_test, y_test):
        print("DEBUG : self train test ")
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

        ## Track the experiments with mlflow (Train Metrics + Model Logging)
        # This will create one run with train metrics and the model artifact.
        self.track_mlflow(best_model, classification_train_metric) 

        y_test_pred = best_model.predict(x_test)
        classification_test_metric = get_classification_score(y_true=y_test, y_pred=y_test_pred)

        ## Track the experiments with mlflow (Test Metrics Only)
        # We use a SEPARATE run to log test metrics for the same model.
        # This is optional, but common practice to separate train/test data.
        with mlflow.start_run():
            mlflow.log_metric("test_f1_score", classification_test_metric.f1_score)
            mlflow.log_metric("test_precision", classification_test_metric.precision_score)
            mlflow.log_metric("test_recall_score", classification_test_metric.recall_score)

        # ------------------- Local Model Persistence -------------------
        preprocessor = load_object(file_path=self.data_transformation_artifact.transformed_object_file_path)

        model_dir_path = os.path.dirname(self.model_trainer_config.trained_model_file_path)
        os.makedirs(model_dir_path, exist_ok=True)

        Network_Model = NetworkModel(preprocessor=preprocessor, model=best_model)
        
        # Save the pipeline/wrapper locally for deployment
        save_object(self.model_trainer_config.trained_model_file_path, obj=Network_Model)
        
        # Save the raw model locally (as done in your original code)
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
    # For testing ModelTrainer, you would initialize it with dummy data/configs here.
    print("DEBUG: Finished model_trainer.py main block")