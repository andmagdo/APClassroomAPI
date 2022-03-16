import requests
from json import dumps
from .models.profile import profile
from .tools.login import login, updateLogin

class APClassroom:
    def __init__(self, username: str, password: str) -> None:
        self.requestSession = requests.Session()
        '''use a request session to keep the same connection open and deal with cookies'''

        '''ignore these, they may be useful later'''
        # var fingerprintHmac = CryptoJS.HmacSHA256(fingerprintHashValue.toString(), nonce)
        # var deviceFingerprint = nonce + \"|\" + fingerprintHmac + \"|\" + fingerprintHashValue
        '''end ignore'''
        self.login = {}
        self.login['user']: str = username
        self.login['pass']: str = password
        '''Login details'''
        self.login['url']: str = "https://prod.idp.collegeboard.org/api/v1/authn"
        '''URL for logging in'''
        self.__login()
        '''Will make the cookies, used to authenticate'''
        self.__updatePayload: dict = None

    def __login(self, __firstUrl:str=None) -> None:
        login(self, __firstUrl)

    def __updateLogin(self, __firstUrl:str=None) -> None:
        updateLogin(self,__firstUrl)


    def getProfile(self) -> profile:
        return profile(self)
