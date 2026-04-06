import sys
from networksecurity.logging import logger

class NetworkSecurityException(Exception):
    def __init__(self,error_message,error_details:sys):
        self.error_message = error_message
        _,_,exc_tb = error_details.exc_info() # exc_info() returns a tuple of three things: Type, Value, and Traceback.
        # _ is used to ignore the first two values
        
        self.lineno=exc_tb.tb_lineno #holds the Traceback object, which contains the "map" of where the code failed.and Extracts the specific line number where the error was triggered.
        self.file_name=exc_tb.tb_frame.f_code.co_filename # holds the name of the file where the error occurred.
    
    def __str__(self):
        return "Error occured in python script name [{0}] line number [{1}] error message [{2}]".format(
        self.file_name, self.lineno, str(self.error_message))
        
if __name__=='__main__':
    try:
        logger.logging.info("Enter the try block")
        a=1/0
        print("This will not be printed",a)
    except Exception as e:
           raise NetworkSecurityException(e,sys)