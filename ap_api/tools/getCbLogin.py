from requests import Session, Response
from .login import updateLogin
from ..errors import LoginException


def getCbLogin(self, maxTries: int = 2) -> None:
    session: Session = self.requestSession

    stepUp(self, session, maxTries)

    getCookies(session, self.login['defaultHeaders'])
    '''Ensure that we have the needed cookies'''

    # print(stepUp.headers['Location'])
    # print(session.cookies.keys())
    # print(stepUp.headers)

    '''Also Need jwtToken. get it from below
    https://sucred.catapult-prod.collegeboard.org/rel/temp-user-aws-creds?cbEnv=pine&appId=366&cbAWSDomains=catapult&cacheNonce={nonce}
    After some testing, the nonce is irrelevant, required, but can be set to 0'''

    '''auth header is sent from here as a cookie 
    (cb_login) https://account.collegeboard.org/login/exchangeToken?code={code}&state=cbAppDurl'''

    '''that site is redirected from here 
    (302 Found) https://prod.idp.collegeboard.org/login/step-up/redirect?stateToken={token}'''

    '''which comes from https://prod.idp.collegeboard.org/api/v1/authn'''


def stepUp(self, session, maxTries: int = 2) -> None:
    tries: int = 0
    self.login['stepUpUrl']: str = self.login['request'].json()['_links']['next']['href']
    stepUp: Response = session.head(self.login['stepUpUrl'], headers=self.login['defaultHeaders'],
                                    allow_redirects=False)
    tries += 1
    while stepUp.status_code != 302:
        updateLogin(self)
        self.login['stepUpUrl']: str = self.login['request'].json()['_links']['next']['href']
        stepUp: Response = self.requestSession.head(self.__stepUpUrl)
        tries += 1
        if tries > maxTries:
            raise LoginException('Maximum number of attempts reached. Check credentials and ensure you are using '
                                 'correct URLs')
    try:
        self.login['tokenExchangeUrl']: str = stepUp.headers['Location']
    except KeyError:
        raise LoginException('KeyError while trying to recieve token exchange url. Check credentials and ensure '
                             'that you are using correct URLs\n'
                             'Traceback can be found above.')


def getCookies(session: Session, headers) -> None:
    """Ensure we have the needed cookies"""
    cookieNames: list = session.cookies.keys()
    neededCookies: list = ['JSESSIONID', 'AMCV_5E1B123F5245B29B0A490D45@AdobeOrg', 'AWSELB', 'AWSELBCORS',
                           '_abck', 'ak_bmsc', 'bm_sz']
    for cookie in neededCookies:
        if cookie not in cookieNames:
            getCookie(session, headers, cookie)


def getCookie(session: Session, headers, cookie: str) -> None:
    # print(cookie)
    if cookie in ['AMCV_5E1B123F5245B29B0A490D45@AdobeOrg']:
        pass
        '''Set via js. I do not know if it is required, and don't know how to make it, used as a tracking cookie
        js at https://assets.adobedtm.com/f740f8a20d94/1dcfc2687ba3/launch-9227a8742d03.min.js, details below
        https://experienceleague.adobe.com/docs/core-services/interface/administration/ec-cookies/cookies-mc.html
        Supposedly (according to the above site) the name may change, but IDK if that even matters.
        The JS says that it is always AMCV_5E1B123F5245B29B0A490D45@AdobeOrg for 
        ["academicmerit.com", "acquia-sites.com", "apscore.org", "cbapis.org", "collegeboard.com", "collegeboard.org", 
        "flossyourscore.com", "springboardonline.com", "springboardonline.org", "powerfaids.org"]
        
        '''
    if cookie in ['JSESSIONID', 'AWSELB', 'AWSELBCORS', '_abck', 'ak_bmsc', 'bm_sz']:
        session.get('https://account.collegeboard.org/login/login?DURL=https://apclassroom.collegeboard.org',
                    headers=headers)
