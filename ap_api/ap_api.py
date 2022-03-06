import requests
from requests import Request
from json import loads, dumps
from urllib.parse import unquote
from .models.profile import profile
from .errors import LoginException


class APClassroom:
    def __init__(self, username: str, password: str) -> None:
        self.requestSession = requests.Session()
        '''use a request session to keep the same connection open and deal with cookies'''

        '''ignore these, they may be useful later'''
        # var fingerprintHmac = CryptoJS.HmacSHA256(fingerprintHashValue.toString(), nonce)
        # var deviceFingerprint = nonce + \"|\" + fingerprintHmac + \"|\" + fingerprintHashValue
        '''end ignore'''
        self.__username: str = username
        self.__password: str = password
        '''Login details'''
        self.__loginUrl = "https://prod.idp.collegeboard.org/api/v1/authn"
        '''URL for logging in'''
        self.__login()
        '''Will make the cookies, used to authenticate'''

    def __login(self) -> None:
        self.requestSession.get("https://myap.collegeboard.org/login")
        '''Get the first round of cookies'''
        self.__clientId: str = self.requestSession.head(
            "https://account.collegeboard.org/login/login?appId=292&DURL=https%3A%2F%2Fwww.collegeboard.org%2F&idp=ECL"
        ).headers["Location"].split("client_id=")[1].split("&")[0]
        '''Get the client ID, needed for the state token. State token is needed for logging in'''

        nonce: str = self.__getLoginNonce()
        '''Get a nonce, needed for a link below'''

        self.__oktaUrl: str = f'https://prod.idp.collegeboard.org/oauth2/aus3koy55cz6p83gt5d7/v1/authorize' \
                              f'?client_id={self.__clientId}&response_type=code&scope=openid+email+profile' \
                              f'&redirect_uri=https://account.collegeboard.org/login/exchangeToken' \
                              f'&state=cbAppDurl&nonce={nonce}'

        self.__oktaRequest: Request = self.requestSession.get(self.__oktaUrl)

        self.__oktaData1: str = self.__oktaRequest.text.split("var oktaData = "
                                                              )[1].split('};')[0] + '}}'.replace("\\x", "%")

        self.__oktaData2: str = self.__oktaData1.replace("function(){", '"function(){').replace(';}}', ';}}"')

        self.__oktaData3: str = unquote(self.__oktaData2)

        self.__oktaData: dict = loads(self.__oktaData3)
        '''Saving all the okta data -- Unsure if it will ever be useful, but better to keep it now then need it later'''

        self.__stateToken: str = self.__oktaData['signIn']['consent']["stateToken"]
        '''get okta login state token from oktaData'''

        self.__loginPayload = dumps({"password": self.__password,
                                     "username": self.__username,
                                     "options": {"warnBeforePasswordExpired": 'false',
                                                 "multiOptionalFactorEnroll": 'false'},
                                     "stateToken": self.__stateToken})
        '''JSON payload for logging in'''

        self.__loginHeaders = {"Accept": "application/json",
                               "Content-Type": "application/json"}

        self.loginRequest = self.requestSession.post(url=self.__loginUrl,
                                                     data=self.__loginPayload,
                                                     headers=self.__loginHeaders)

        if self.loginRequest.status_code != 200:
            self.__loginRequest = self.loginRequest.json()
            if "E0000011" in self.__loginRequest["errorCode"]:
                '''invalid token error. seems random. Best fix is to try again'''
                self.__login()
            else:
                raise LoginException(f'Error code: {self.__loginRequest["errorCode"]}\n'
                                     f'Error description: {self.__loginRequest["errorSummary"]}')

        '''Login, keep the request for later'''

    def updateLogin(self) -> None:
        self.__login()

    def __getLoginNonce(self) -> str:
        return self.requestSession.post("https://prod.idp.collegeboard.org/api/v1/internal/device/nonce"
                                        ).json()['nonce']

    def getProfile(self) -> profile:
        return profile(self)
