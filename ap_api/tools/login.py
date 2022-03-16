from requests import Response
from json import loads, dumps
from urllib.parse import unquote
from ..errors import LoginException

def login(self, __firstUrl: str) -> None:

    if not __firstUrl:
        __firstUrl = "https://account.collegeboard.org/login/login?appId=292&DURL=https%3A%2F%2Fmy.collegeboard.org%2Fprofile%2Finformation%2F&idp=ECL"

    self.requestSession.get("https://www.collegeboard.org")
    self.__firstRequest: Response = self.requestSession.head(__firstUrl)
    self.__clientId: str = self.__firstRequest.headers["Location"].split("client_id=")[1].split("&")[0]
    '''Get the client ID, needed for the state token. State token is needed for logging in'''

    nonce: str = getLoginNonce(self)
    '''Get a nonce, needed for a link below'''

    self.__oktaUrl: str = f'https://prod.idp.collegeboard.org/oauth2/aus3koy55cz6p83gt5d7/v1/authorize' \
                          f'?client_id={self.__clientId}&response_type=code&scope=openid+email+profile' \
                          f'&redirect_uri=https://account.collegeboard.org/login/exchangeToken' \
                          f'&state=cbAppDurl&nonce={nonce}'

    self.__oktaRequest: Response = self.requestSession.get(self.__oktaUrl)

    self.__oktaData1: str = self.__oktaRequest.text.split("var oktaData = ")[1].split('};')[0] + '}}'

    self.__oktaData2: str = self.__oktaData1.replace("function(){", '"function(){').replace(';}}', ';}}"')

    self.__oktaData3: str = unquote(self.__oktaData2).replace("\\x", "%")

    self.__oktaData: dict = loads(self.__oktaData3)
    '''Saving all the okta data -- Unsure if it will ever be useful, but better to keep it now then need it later'''

    self.stateToken: str = self.__oktaData['signIn']['consent']["stateToken"]
    '''get okta login state token from oktaData'''

    self.__loginPayload = dumps({"password": self.login['pass'],
                                 "username": self.login['user'],
                                 "options": {"warnBeforePasswordExpired": 'false',
                                             "multiOptionalFactorEnroll": 'false'},
                                 "stateToken": self.stateToken})
    '''JSON payload for logging in'''

    self.__loginHeaders = {"Accept": "application/json",
                           "Content-Type": "application/json"}

    self.loginRequest = self.requestSession.post(url=self.login['url'],
                                                 data=self.__loginPayload,
                                                 headers=self.__loginHeaders)

    if self.loginRequest.status_code != 200:
        self.__loginRequest = self.loginRequest.json()
        if "E0000011" in self.__loginRequest["errorCode"]:
            '''invalid token error. seems random. Best fix is to try again, even though I hate recursive functions'''
            login(self, __firstUrl)
        elif 401 == self.loginRequest.status_code:
            raise LoginException(f'Invalid username or password\n'
                                 f'Error code: {self.__loginRequest["errorCode"]}\n'
                                 f'Error description: {self.__loginRequest["errorSummary"]}'
                                 )
        else:
            raise LoginException(f'Error code: {self.__loginRequest["errorCode"]}\n'
                                 f'Error description: {self.__loginRequest["errorSummary"]}')

    '''Login, keep the request for later'''

def getLoginNonce(self) -> str:
    return self.requestSession.post("https://prod.idp.collegeboard.org/api/v1/internal/device/nonce"
                                    ).json()['nonce']


def updateLogin(self, __firstUrl:str=None) -> None:
    if __firstUrl:
        login(self,__firstUrl)
        return
    self.__updatePayload = dumps({"password": self.__password, "stateToken": self.stateToken})
    self.loginRequest = self.requestSession.get('https://prod.idp.collegeboard.org/api/v1/authn/factors/password/verify?rememberDevice=false', data=self.__updatePayload)



    '''does this work?
    https://cbaccount.collegeboard.org/iamweb/secure/smartUpdate?DURL=https://apclassroom.collegeboard.org/10/assessments/assignments'''
