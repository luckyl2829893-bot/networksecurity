from networksecurity.Component.data_ingestion import DataIngestion
from networksecurity.Exception.exception import NetworkSecurityException
from networksecurity.Logging.logger import logging
from networksecurity.Entity.config_entity import DataIngestionConfig
from networksecurity.Entity.config_entity import TrainingPipelineConfig
import sys

if __name__== '__main__':
    try:

        trainingPipelineconfig=TrainingPipelineConfig()
        dataIngestionconfig= DataIngestionConfig(trainingPipelineconfig)
        data_ingestion=DataIngestion(dataIngestionconfig)
        logging.info("Initiate the data ingestion")
        dataingestionartifact=data_ingestion.initiate_data_ingestion()
        print(dataingestionartifact)



    except Exception as e:
        raise NetworkSecurityException(e,sys)