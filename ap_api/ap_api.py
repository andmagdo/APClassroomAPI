import requests
from .models.profile import profile
from .tools import login, updateLogin
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
        try:
            login(self)
        except KeyError:
            raise LoginException(f"Key error in login \n")
        '''Will make the cookies, used to authenticate'''


    def loginUpdate(self, __firstUrl: str = None) -> None:
        updateLogin(self, __firstUrl)

    def getProfile(self) -> profile:
        return profile(self)

    def __initLoginDict(self) -> None:
        self.login['defaultHeaders']: dict = {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,application/json,'
                      '*/*;q=0.8',
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept-Language': 'en-US,en;q=0.9',
            'Cache-Control': 'no - cache',
            'Connection': 'keep-alive',
            'Pragma': 'no-cache',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'Upgrade-Insecure-Requests': '1',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) '
                          'Chrome/83.0.4103.116 Safari/537.36 '
        }
