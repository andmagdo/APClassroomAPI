from json import loads, dumps, JSONDecodeError
from urllib.parse import unquote

from requests import Response

from ..errors import LoginException, InvalidCredentials


def login(self, firstUrl: str = None) -> None:
    """Normal function to log in to collegeboard"""

    initCookies(self)

    getClientId(self, firstUrl)
    '''This does return a tuple with data, but already saves the information in the main login dictionary'''

    getStateToken(self)
    '''This does return a string with the info, but also already saves the information to the main login dictionary'''

    makeLoginRequest(self)
    '''For fear of repeating myself, this returns a Response object, but also saves it'''

    '''Before finishing, check if there are issues'''

    '''Error Handling'''
    errorCheck(self, firstUrl)


def getLoginNonce(self) -> str:
    return self.requestSession.post("https://prod.idp.collegeboard.org/api/v1/internal/device/nonce",
                                    headers=self.login['defaultHeaders']).json()['nonce']


def updateLogin(self, __firstUrl: str = None) -> None:
    if __firstUrl:
        login(self, __firstUrl)
        return

    headers = self.login['defaultHeaders']
    headers["Content-Type"] = "application/json"

    self.login['payload']: str = dumps({"password": self.login['pass'], "stateToken": self.stateToken})
    self.login['request']: Response = self.requestSession.get(
        'https://prod.idp.collegeboard.org/api/v1/authn/factors/password/verify?rememberDevice=false',
        data=self.login['payload'], headers=headers)

    '''does this work? https://cbaccount.collegeboard.org/iamweb/secure/smartUpdate?DURL=https://apclassroom
    .collegeboard.org/10/assessments/assignments '''


def initCookies(self) -> None:
    """Connect to the www.collegeboard.org website and get the cookies in the request session"""
    self.requestSession.get("https://www.collegeboard.org", headers=self.login['defaultHeaders'])
    '''Get initial cookies'''
    return


def getFirstLoginPage(self, url) -> Response:
    """Connect to an accounts page"""
    if not url:
        url = "https://account.collegeboard.org/login/login?appId=292&DURL=https%3A%2F%2Fmy.collegeboard.org" \
              "%2Fprofile%2Finformation%2F&idp=ECL"

    self.login['firstRequest']: Response = self.requestSession.head(url, headers=self.login['defaultHeaders'])
    if not self.login['firstRequest'].is_redirect:
        raise LoginException("The request for the client ID must be a redirect. It is not.")

    return self.login['firstRequest']


def getClientId(self, url) -> tuple[Response, str]:
    """Get the client ID, needed for the state token. State token is needed for logging in

    It does this by requesting a login page that redirects to a page which contains the client ID as a query parameter.
    This ID is then saved in the login dictionary.

    Args:
        self (APClassroom): The main API object
        url (str): The URL of the login page.

    Returns:
        tuple[Response, str]: The response object and the client ID
    """
    request = getFirstLoginPage(self, url)
    self.login['clientId']: str = request.headers["Location"].split("client_id=")[1].split("&")[0]

    return request, self.login['clientId']


def getStateToken(self) -> str:
    nonce: str = getLoginNonce(self)
    '''Get a nonce, needed for a link below'''

    self.login['oktaUrl']: str = f'https://prod.idp.collegeboard.org/oauth2/aus3koy55cz6p83gt5d7/v1/authorize' \
                                 f'?client_id={self.login["clientId"]}&response_type=code&scope=openid+email+profile' \
                                 f'&redirect_uri=https://account.collegeboard.org/login/exchangeToken' \
                                 f'&state=cbAppDurl&nonce={nonce}'

    self.login['oktaRequest']: Response = self.requestSession.get(self.login['oktaUrl'],
                                                                  headers=self.login['defaultHeaders'])

    self.login['oktaData1']: str = self.login['oktaRequest'].text.split("var oktaData = ")[1].split('};')[0] + '}}'

    self.login['oktaData2']: str = self.login['oktaData1'].replace("function(){", '"function(){').replace(';}}', ';}}"')

    self.login['oktaData3']: str = unquote(self.login['oktaData2']).replace("\\x", "%")

    self.login['oktaData']: dict = loads(self.login['oktaData3'])
    '''Saving all the okta data -- Unsure if it will ever be useful, but better to keep it now then need it later'''

    self.login['stateToken']: str = self.login['oktaData']['signIn']['consent']["stateToken"]
    '''get okta login state token from oktaData'''

    return self.login['stateToken']


def makeLoginRequest(self) -> Response:
    self.login['payload']: str = dumps({"password": self.login['pass'],
                                        "username": self.login['user'],
                                        "options": {"warnBeforePasswordExpired": 'false',
                                                    "multiOptionalFactorEnroll": 'false'},
                                        "stateToken": self.login['stateToken']})
    '''JSON payload for logging in'''

    headers = self.login['defaultHeaders']
    headers["Content-Type"] = "application/json"
    self.login['request'] = self.requestSession.post(url=self.login['url'],
                                                     data=self.login['payload'],
                                                     headers=headers)

    return Response


def errorCheck(self, firstUrl) -> None:
    if self.login['request'].status_code != 200:
        # print(self.login['request'].content.decode('utf-8'))
        try:
            self.login['requestJson'] = self.login['request'].json()
        except JSONDecodeError:
            raise LoginException(f'Error decoding error data. Traceback above and raw website output below\n'
                                 f'{self.login["request"].content}')
        if "E0000011" in self.login['requestJson']["errorCode"]:
            '''invalid token error. seems random. Best fix is to try again, even though I hate recursive functions'''
            login(self, firstUrl)
        elif 401 == self.loginRequest.status_code:
            raise InvalidCredentials(f'Invalid username or password\n'
                                     f'Error code: {self.__loginRequest["errorCode"]}\n'
                                     f'Error description: {self.__loginRequest["errorSummary"]}'
                                     )
        else:
            raise LoginException(f'Error code: {self.__loginRequest["errorCode"]}\n'
                                 f'Error description: {self.__loginRequest["errorSummary"]}')
