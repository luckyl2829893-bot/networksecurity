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

# dagshub init was moved inside ModelTrainer to avoid module-level execution.

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

        if not model_report:
            raise Exception("No model evaluation results found. Check evaluate_models in utils.py")

        ## To get best model score from dict by F1 score
        best_model_score = max(metrics["f1"] for metrics in model_report.values())

        ## To get best model name from dict
        best_model_names = [
            name for name, metrics in model_report.items() if metrics["f1"] == best_model_score
        ]
        
        if not best_model_names:
            raise Exception("Could not identify a best model from the evaluation report.")
            
        best_model_name = best_model_names[0]
        best_model = models[best_model_name]
        
        y_train_pred = best_model.predict(X_train)
        classification_train_metric = get_classification_score(y_true=y_train, y_pred=y_train_pred)
        
        y_test_pred = best_model.predict(x_test)
        classification_test_metric = get_classification_score(y_true=y_test, y_pred=y_test_pred)

        ## Track the experiments with mlflow
        try:
            print("Debug : Logging metrics and model to MLflow/DagsHub...")
            with mlflow.start_run() as run:
                # Log Train Metrics
                mlflow.log_metric("train_f1_score", classification_train_metric.f1_score)
                mlflow.log_metric("train_precision", classification_train_metric.precision_score)
                mlflow.log_metric("train_recall", classification_train_metric.recall_score)
                
                # Log Test Metrics
                mlflow.log_metric("test_f1_score", classification_test_metric.f1_score)
                mlflow.log_metric("test_precision", classification_test_metric.precision_score)
                mlflow.log_metric("test_recall", classification_test_metric.recall_score)
                
                # Log the best model
                mlflow.sklearn.log_model(sk_model=best_model, artifact_path="model_artifact")
                print(f"Successfully logged to DagsHub Run ID: {run.info.run_id}")
        except Exception as e:
            print(f"--- [MLflow Warning] Failed to log to DagsHub: {e} ---")

        # ------------------- SHAP Explainability -----------------------
        try:
            import shap
            import matplotlib.pyplot as plt
            import numpy as np

            print("Generating SHAP Explainability Plots...")
            explain_dir = os.path.join("Artifacts", "Explainability")
            os.makedirs(explain_dir, exist_ok=True)

            # Using a generic Explainer or selecting based on model type
            if "Forest" in str(type(best_model)) or "Tree" in str(type(best_model)) or "Boosting" in str(type(best_model)):
                explainer = shap.TreeExplainer(best_model)
            elif "Logistic" in str(type(best_model)) or "Linear" in str(type(best_model)):
                explainer = shap.LinearExplainer(best_model, x_test)
            else:
                explainer = shap.Explainer(best_model, x_test)
                
            shap_values = explainer.shap_values(x_test)
            
            # Define feature names for better plots
            feature_names = [
                "having_IP_Address","URL_Length","Shortining_Service","having_At_Symbol","double_slash_redirecting",
                "Prefix_Suffix","having_Sub_Domain","SSLfinal_State","Domain_registeration_length","Favicon",
                "port","HTTPS_token","Request_URL","URL_of_Anchor","Links_in_tags","SFH","Submitting_to_email",
                "Abnormal_URL","Redirect","on_mouseover","RightClick","popUpWidnow","Iframe","age_of_domain",
                "DNSRecord","web_traffic","Page_Rank","Google_Index","Links_pointing_to_page","Statistical_report"
            ]
            
            # Handle different SHAP output formats (list for multi-class/binary or array)
            if isinstance(shap_values, list):
                # Usually [class0_vals, class1_vals]
                shap_vals_to_plot = shap_values[1]
                expected_value = explainer.expected_value[1]
            elif len(shap_values.shape) == 3:
                # Shape (N, features, classes) -> take class 1
                shap_vals_to_plot = shap_values[:, :, 1]
                expected_value = explainer.expected_value[1]
            else:
                shap_vals_to_plot = shap_values
                expected_value = explainer.expected_value

            # 1. Summary Plot (Global Explainability)
            plt.figure(figsize=(10, 6))
            shap.summary_plot(shap_vals_to_plot, x_test, feature_names=feature_names, show=False)
            plt.tight_layout()
            summary_path = os.path.join(explain_dir, "shap_summary_plot.png")
            plt.savefig(summary_path, bbox_inches='tight', dpi=300)
            plt.close()
            print(f"SHAP Summary Plot saved to {summary_path}")

            # 2. Waterfall Plot for a single instance (Local Explainability)
            plt.figure(figsize=(12, 8))
            
            # Ensure values are 1D (features,)
            instance_vals = shap_vals_to_plot[0]
            if len(instance_vals.shape) > 1:
                instance_vals = instance_vals[:, 1] # Fallback if still 2D
                
            # Create a SHAP Explanation object for the waterfall plot
            explanation = shap.Explanation(
                values=instance_vals, 
                base_values=expected_value, 
                data=x_test[0],
                feature_names=feature_names
            )
            shap.waterfall_plot(explanation, show=False)
            plt.tight_layout()
            waterfall_path = os.path.join(explain_dir, "shap_waterfall_plot.png")
            plt.savefig(waterfall_path, bbox_inches='tight', dpi=300)
            plt.close()
            print(f"SHAP Waterfall Plot saved to {waterfall_path}")
            
        except Exception as e:
            print(f"Error generating SHAP plots: {e}")

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