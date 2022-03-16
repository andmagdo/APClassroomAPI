from requests import Response
from json import loads, dumps
from urllib.parse import unquote
from ..errors import LoginException, InvalidCredentials
from simplejson import JSONDecodeError

def login(self, __firstUrl:str = None) -> None:
    if not __firstUrl:
        __firstUrl = "https://account.collegeboard.org/login/login?appId=292&DURL=https%3A%2F%2Fmy.collegeboard.org" \
                     "%2Fprofile%2Finformation%2F&idp=ECL"

    self.requestSession.get("https://www.collegeboard.org")
    '''Get initial cookies'''


    self.login['firstRequest']: Response = self.requestSession.head(__firstUrl, headers=self.login['defaultHeaders'])
    if not self.login['firstRequest'].is_redirect:
        raise LoginException("The request for the client ID must be a redirect. It is not.")


    self.login['clientId']: str = self.login['firstRequest'].headers["Location"].split("client_id=")[1].split("&")[0]
    '''Get the client ID, needed for the state token. State token is needed for logging in'''

    nonce: str = getLoginNonce(self)
    '''Get a nonce, needed for a link below'''

    self.login['oktaUrl']: str = f'https://prod.idp.collegeboard.org/oauth2/aus3koy55cz6p83gt5d7/v1/authorize' \
                          f'?client_id={self.login["clientId"]}&response_type=code&scope=openid+email+profile' \
                          f'&redirect_uri=https://account.collegeboard.org/login/exchangeToken' \
                          f'&state=cbAppDurl&nonce={nonce}'

    self.login['oktaRequest']: Response = self.requestSession.get(self.login['oktaUrl'])

    self.login['oktaData1']: str = self.login['oktaRequest'].text.split("var oktaData = ")[1].split('};')[0] + '}}'

    self.login['oktaData2']: str = self.login['oktaData1'].replace("function(){", '"function(){').replace(';}}', ';}}"')

    self.login['oktaData3']: str = unquote(self.login['oktaData2']).replace("\\x", "%")

    self.login['oktaData']: dict = loads(self.login['oktaData3'])
    '''Saving all the okta data -- Unsure if it will ever be useful, but better to keep it now then need it later'''

    self.login['stateToken']: str = self.login['oktaData']['signIn']['consent']["stateToken"]
    '''get okta login state token from oktaData'''

    self.__loginPayload = dumps({"password": self.login['pass'],
                                 "username": self.login['user'],
                                 "options": {"warnBeforePasswordExpired": 'false',
                                             "multiOptionalFactorEnroll": 'false'},
                                 "stateToken": self.login['stateToken']})
    '''JSON payload for logging in'''

    headers=self.login['defaultHeaders']
    headers["Content-Type"] = "application/json"
    self.login['request'] = self.requestSession.post(url=self.login['url'],
                                                 data=self.__loginPayload,
                                                 headers=headers)

    '''Error Handling'''
    if self.login['request'].status_code != 200:
        print(self.login['request'].content.decode('utf-8'))
        try:
            self.__loginRequest = self.login['request'].json()
        except JSONDecodeError:
            raise LoginException(f'Error decoding error data. Traceback above and raw website output below\n'
                                 f'{self.login["request"].content}')
        if "E0000011" in self.__loginRequest["errorCode"]:
            '''invalid token error. seems random. Best fix is to try again, even though I hate recursive functions'''
            login(self, __firstUrl)
        elif 401 == self.loginRequest.status_code:
            raise InvalidCredentials(f'Invalid username or password\n'
                                 f'Error code: {self.__loginRequest["errorCode"]}\n'
                                 f'Error description: {self.__loginRequest["errorSummary"]}'
                                 )
        else:
            raise LoginException(f'Error code: {self.__loginRequest["errorCode"]}\n'
                                 f'Error description: {self.__loginRequest["errorSummary"]}')



def getLoginNonce(self) -> str:
    return self.requestSession.post("https://prod.idp.collegeboard.org/api/v1/internal/device/nonce"
                                    ).json()['nonce']


def updateLogin(self, __firstUrl: str = None) -> None:
    if __firstUrl:
        login(self, __firstUrl)
        return
    self.__updatePayload = dumps({"password": self.__password, "stateToken": self.stateToken})
    self.loginRequest = self.requestSession.get(
        'https://prod.idp.collegeboard.org/api/v1/authn/factors/password/verify?rememberDevice=false',
        data=self.__updatePayload)

    '''does this work? https://cbaccount.collegeboard.org/iamweb/secure/smartUpdate?DURL=https://apclassroom
    .collegeboard.org/10/assessments/assignments '''
