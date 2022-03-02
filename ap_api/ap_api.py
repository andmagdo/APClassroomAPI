import requests
import random
currentOkta:str = "okta-signin-widget-5.9.4"

class APClassroom:
    def __init__(self, username:str, password:str):
        self.deviceFingerprint:str =
        self.oktaAgent
        self.requestSession = requests.Session()
        """use a request session to keep the same connection open"""
        self.deviceFingerprint: str =
        self.oktaAgent:         str = currentOkta
        self.__username:        str = username
        self.__password:        str = password
        self.token:             str = self.login()
        """Will return the bearer token, used to authenticate"""

    def login(self) -> str:
        url = "https://prod.idp.collegeboard.org/api/v1/authn"
