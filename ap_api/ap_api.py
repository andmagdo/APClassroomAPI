import requests
from .models.profile import profile
from .tools.login import login, updateLogin
from .errors import LoginException

class APClassroom:
    def __init__(self, username: str, password: str) -> None:
        self.requestSession = requests.Session()
        '''use a request session to keep the same connection open and deal with cookies'''

        '''ignore these, they may be useful later'''
        # var fingerprintHmac = CryptoJS.HmacSHA256(fingerprintHashValue.toString(), nonce)
        # var deviceFingerprint = nonce + \"|\" + fingerprintHmac + \"|\" + fingerprintHashValue
        '''end ignore'''
        self.login = {}
        self.__initLoginDict()
        self.login['user']: str = username
        self.login['pass']: str = password
        '''Login details'''
        self.login['url']: str = "https://prod.idp.collegeboard.org/api/v1/authn"
        '''URL for logging in'''
        self.__login()
        '''Will make the cookies, used to authenticate'''
        self.__updatePayload: dict = None

    def __login(self, __firstUrl: str = None) -> None:
        try:
            login(self, __firstUrl)
        except KeyError as e:
            raise LoginException(f"Key error in login \n")

    def __updateLogin(self, __firstUrl: str = None) -> None:
        updateLogin(self, __firstUrl)

    def getProfile(self) -> profile:
        return profile(self)

    def __initLoginDict(self) -> None:
        """Initialize the login dictionary in order to ensure that KeyErrors do not result"""
        self.login['user']: str
        self.login['pass']: str
        self.login['clientId']: str

        self.login['defaultHeaders']: dict = {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept-Language': 'en-US,en;q=0.9',
            'Cache-Control':'no - cache',
            'Connection': 'keep-alive',
            'Host': 'account.collegeboard.org',
            'Pragma': 'no-cache',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'Upgrade-Insecure-Requests': '1',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36'
        }
