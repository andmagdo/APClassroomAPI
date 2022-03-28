from json import loads, dumps, JSONDecodeError
from urllib.parse import unquote

from requests import Session, Response

from ..errors import LoginException, InvalidCredentials


def login(self, firstUrl: str = None) -> None:
    """Normal function to log in to collegeboard"""

    # to get Bearer token, https://am-accounts-production.collegeboard.org/account/api/
    # with json of {"namespace":"st","sessionId":"{CBLOGIN}","username":"{USERNAME} "}

    initCookies(self)

    getClientId(self, firstUrl)
    '''This does return a tuple with data, but already saves the information in the main login dictionary'''

    getStateToken(self)
    '''This does return a string with the info, but also already saves the information to the main login dictionary'''

    makeLoginRequest(self)
    '''For fear of repeating myself, this returns a Response object, but also saves it'''

    '''Before finishing, check if there are issues'''
    errorCheck(self, firstUrl)

    getCbLogin(self)


def initCookies(self) -> None:
    """Connect to the www.collegeboard.org website and get the cookies in the request session"""
    self.requestSession.get("https://www.collegeboard.org", headers=self.login['defaultHeaders'])
    '''Get initial cookies'''
    return


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

    data1: str = self.login['oktaRequest'].text.split("var oktaData = ")[1].split('};')[0] + '}}'

    data2: str = data1.replace("function(){", '"function(){').replace(';}}', ';}}"')

    data3: str = unquote(data2).replace("\\x", "%")

    self.login['oktaData']: dict = loads(data3)
    '''Saving all the okta data -- Unsure if it will ever be useful, but better to keep it now then need it later'''

    self.login['stateToken']: str = self.login['oktaData']['signIn']['consent']["stateToken"]
    '''get okta login state token from oktaData'''

    return self.login['stateToken']


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


def getFirstLoginPage(self, url) -> Response:
    """Connect to an accounts page"""
    if not url:
        url = "https://account.collegeboard.org/login/login?appId=292&DURL=https%3A%2F%2Fmy.collegeboard.org" \
              "%2Fprofile%2Finformation%2F&idp=ECL"

    self.login['loginPageRequest']: Response = self.requestSession.head(url, headers=self.login['defaultHeaders'])
    if not self.login['loginPageRequest'].is_redirect:
        raise LoginException("The request for the client ID must be a redirect. It is not.")

    return self.login['loginPageRequest']


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


def getCbLogin(self, maxTries: int = 2) -> None:
    """Grabs the CbLogin token and adds it to the login dictionary"""
    session: Session = self.requestSession

    stepUp(self, session, maxTries)

    getCookies(session, self.login['defaultHeaders'])
    '''Ensure that we have the needed cookies'''

    # print(stepUp.headers['Location'])
    # print(session.cookies.keys())
    # print(stepUp.headers)

    tokenExchange(self, session, self.login['defaultHeaders'])

    '''Also Need jwtToken. get it from below
    https://sucred.catapult-prod.collegeboard.org/rel/temp-user-aws-creds?cbEnv=pine&appId=366&cbAWSDomains=catapult&cacheNonce={nonce}
    After some testing, the nonce is irrelevant, required, but can be set to 0'''

    '''auth header is sent from here as a cookie 
    (cb_login) https://account.collegeboard.org/login/exchangeToken?code={code}&state=cbAppDurl'''

    '''that site is redirected from here 
    (302 Found) https://prod.idp.collegeboard.org/login/step-up/redirect?stateToken={token}'''

    '''which comes from https://prod.idp.collegeboard.org/api/v1/authn'''


def stepUp(self, session: Session, maxTries: int = 1) -> None:
    """Contact the stepUp part of the login process

    Args:
        self: Pass the APClassroom object
        session (Session): The session to use for the request
        maxTries (int, optional): The maximum number of times to try the request. Defaults to 1.
    """

    '''Set this cookie, normally set via js, I am unsure if it is needed'''
    session.cookies.set('oktaStateToken', self.login['stateToken'])

    """Connect to the stepup site in order to get the link that gets the CBlogin"""
    tries: int = 0
    self.login['stepUpUrl']: str = self.login['request'].json()['_links']['next']['href']
    stepUp: Response = session.head(self.login['stepUpUrl'], headers=self.login['defaultHeaders'],
                                    allow_redirects=False)
    tries += 1
    while stepUp.status_code != 302:
        if tries >= maxTries:
            raise LoginException('Maximum number of attempts reached. Check credentials and ensure you are using '
                                 'correct URLs')
        updateLogin(self)
        self.login['stepUpUrl']: str = self.login['request'].json()['_links']['next']['href']
        stepUp: Response = self.requestSession.head(self.__stepUpUrl, headers=self.login['defaultHeaders'])
        tries += 1

    try:
        self.login['tokenExchangeUrl']: str = stepUp.headers['Location']
    except KeyError:
        raise LoginException('KeyError while trying to recieve token exchange url. Check credentials and ensure '
                             'that you are using correct URLs\n'
                             'Traceback can be found above.')


def getCookies(session: Session, headers: dict) -> None:
    """Ensure we have the needed cookies

    Doing this by accepting both the session object and the headers, because Collegeboard requires a user agent"""
    cookieNames: list = session.cookies.keys()
    neededCookies: list = ['JSESSIONID', 'AMCV_5E1B123F5245B29B0A490D45@AdobeOrg', 'AWSELB', 'AWSELBCORS',
                           '_abck', 'ak_bmsc', 'bm_sz']
    for cookie in neededCookies:
        if cookie not in cookieNames:
            getCookie(session, headers, cookie)


def getCookie(session: Session, headers: dict, cookie: str) -> None:
    """Check see what cookies are needed and remedy the issue"""
    # print(cookie)
    if cookie in ['AMCV_5E1B123F5245B29B0A490D45@AdobeOrg']:
        pass
        '''Set via js. I do not know if it is required, and don't know how to make it, used as a tracking cookie
        js at https://assets.adobedtm.com/f740f8a20d94/1dcfc2687ba3/launch-9227a8742d03.min.js, details below
        https://experienceleague.adobe.com/docs/core-services/interface/administration/ec-cookies/cookies-mc.html
        Supposedly (according to the above site) the name may change, but IDK if that even matters.
        '''
    if cookie in ['JSESSIONID', 'AWSELB', 'AWSELBCORS', '_abck', 'ak_bmsc', 'bm_sz']:
        session.get('https://account.collegeboard.org/login/login?DURL=https://apclassroom.collegeboard.org',
                    headers=headers)


def tokenExchange(self, session: Session, headers: dict) -> None:
    """Gets the CBlogin Headers"""
    # session.cookies.set('AMCV_5E1B123F5245B29B0A490D45@AdobeOrg',"-2121179033|MCIDTS|19067|MCMID|56759820167809519468062158045823210293|vVersion|5.3.0")

    headers["Host"] = "account.collegeboard.org"

    # print(session.options(self.login['tokenExchangeUrl'],
    #                 headers=headers).headers)

    # tryThis(self, session, headers, self.login['tokenExchangeUrl'])

    print('"' + self.login['tokenExchangeUrl'] + '"')

    self.login['tokenExchangeRequest']: Response = session.head(self.login['tokenExchangeUrl'],
                                                                headers=headers,
                                                                allow_redirects=False)

    if not self.login['tokenExchangeRequest'].is_redirect:
        print(session.cookies.keys())
        print(self.login['tokenExchangeRequest'].headers)
        raise LoginException('Token exchange request did not return a redirect. Ensure that the URL is correct')

    print(self.login['tokenExchangeRequest'].headers['Location'])

    print(self.login['tokenExchangeRequest'].headers)

    print(session.cookies.keys())

    print(self.login['tokenExchangeRequest'].request.headers)


# def tryThis(self, session: Session, headers:dict, url:str):
#     'https://prod.idp.collegeboard.org/oauth2/aus3koy55cz6p83gt5d7/v1/authorize?client_id=0oa3koxakyZGbffcq5d7&response_type=code&scope=openid+email+profile&redirect_uri=https://account.collegeboard.org/login/exchangeToken&state=cbAppDurl&nonce=MTY0Nzk2MjMzMjc1Nw=='
#     tryUrl: str = f'https://prod.idp.collegeboard.org/oauth2/aus3koy55cz6p83gt5d7/v1/authorize?client_id=' \
#                   f'{self.login["clientId"]}&response_type=code&scope=openid+email+profile&redirect_uri=' \
#                   f'{url}&nonce=0'
#     print(session.get(tryUrl, headers=headers))


'''
Login process:

We need the Bearer authentication token, which is a JWT token.

We can get this via https://am-accounts-production.collegeboard.org/account/api/
with the json {"namespace":"st","sessionId":"{CB_Login token}","username":"{username all caps}"}

Get the CB_Login token by going to https://account.collegeboard.org/login/exchangeToken?code={random}&state=cbAppDurl
it is sent as a cookie when this site is a redirect

Get that redirect url from another redirect url
https://prod.idp.collegeboard.org/login/step-up/redirect?stateToken={stateToken}
    
    This uses the following cookies:
              "name": "_abck",
              "name": "ak_bmsc",
              "name": "bm_sz",
              "name": "JSESSIONID",
              "name": "t",
              "name": "DT",
              "name": "oktaStateToken",
              "name": "bm_sv",

We get that link from the authn link used to initially log in

'''
