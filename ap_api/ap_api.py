import requests
import random
import re
from json import loads, dumps
from urllib.parse import unquote


class APClassroom:
    def __init__(self, username: str, password: str):
        self.__requestSession = requests.Session()
        '''use a request session to keep the same connection open and deal with cookies'''

        '''ignore these, they may be useful later'''
        # var fingerprintHmac = CryptoJS.HmacSHA256(fingerprintHashValue.toString(), nonce)
        # var deviceFingerprint = nonce + \"|\" + fingerprintHmac + \"|\" + fingerprintHashValue
        '''end ignore'''
        self.__username: str = username
        self.__password: str = password
        '''Login details'''
        self.__loginURL = "https://prod.idp.collegeboard.org/api/v1/authn"
        '''URL for logging in'''
        self.__token: str = self.login()
        '''Will return the bearer token, used to authenticate'''

    def login(self) -> str:
        self.__requestSession.get("https://myap.collegeboard.org/login")
        '''Get the first round of cookies'''
        self.clientId: str = self.__requestSession.head(
            "https://account.collegeboard.org/login/login?appId=292&DURL=https%3A%2F%2Fwww.collegeboard.org%2F&idp=ECL"
        ).headers["Location"].split("client_id=")[1].split("&")[0]
        '''Get the client ID, needed for the state token. State token is needed for the '''
        nonce = self.__getLoginNonce()
        '''Get a nonce, needed for a link below'''

        # https://prod.idp.collegeboard.org/oauth2/aus3koy55cz6p83gt5d7/v1/authorize?client_id=0oa3koxakyZGbffcq5d7&response_type=code&scope=openid+email+profile&redirect_uri=https://account.collegeboard.org/login/exchangeToken&state=cbAppDurl&nonce=MTY0NjQxMjQzNTEzNg==
        self.__oktaData: dict = loads(unquote(self.__requestSession.get(
            f'''https://prod.idp.collegeboard.org/oauth2/aus3koy55cz6p83gt5d7/v1/authorize?client_id={self.clientId
            }&response_type=code&scope=openid+email+profile&redirect_uri=https://account.collegeboard.org/login/exchangeToken&state=cbAppDurl&nonce={nonce}'''
                ).text.split("var oktaData = ")[1].split('};')[0] + '}}'
                    ).replace("\\x", "%").replace("function(){",'"function(){').replace(';}}',';}}"'))
        '''Saving all the okta data -- No clue if it will ever be useful, but better to keep it now then need it later'''
        '''{'redirectUri': 'https://prod.idp.collegeboard.org/oauth2/v1/authorize/redirect?okta_key=fuBwvtRlO-qzfIogLHJ1c_69DrPCRiJVkUTh236O0YE', 'isMobileSso': False, 'fromUri': '/oauth2/v1/authorize/redirect?okta_key=fuBwvtRlO-qzfIogLHJ1c_69DrPCRiJVkUTh236O0YE', 'isMobileClientLogin': False, 'requestContext': {'target': {'clientId': '0oa3koxakyZGbffcq5d7', 'name': 'oidc_client', 'links': {}, 'label': 'paLoginCloud - Default', 'type': {}}, 'authentication': {'request': {'scope': 'openid email profile', 'response_type': 'code', 'state': 'cbAppDurl', 'redirect_uri': 'https://account.collegeboard.org/login/exchangeToken', 'response_mode': 'query'}, 'protocol': {}, 'amr': [], 'client': {'name': 'paLoginCloud - Default', 'links': {}, 'id': '0oa3koxakyZGbffcq5d7'}, 'issuer': {'name': 'cb-custom-auth-server', 'id': 'aus3koy55cz6p83gt5d7', 'uri': 'https://prod.idp.collegeboard.org/oauth2/aus3koy55cz6p83gt5d7'}}}, 'signIn': {'logoText': 'College Board logo', 'language': 'en', 'consent': {'cancel': "function(){window.location.href='https://prod.idp.collegeboard.org/login/step-up/redirect?stateToken=004NxJtd5R-tYk_oRjf7VNGgxP3-0vfEMlWgep5Ddb';}}", 'i18n': {'en': {'mfa.challenge.password.placeholder': 'Password', 'help': 'Help', 'password.forgot.email.or.username.tooltip': 'Enter your email', 'needhelp': 'Need help signing in?', 'primaryauth.username.placeholder': 'Email Address', 'password.forgot.email.or.username.placeholder': 'Enter your email', 'account.unlock.email.or.username.tooltip': 'Enter your email', 'unlockaccount': 'Unlock account?', 'account.unlock.email.or.username.placeholder': 'Enter your email', 'primaryauth.password.placeholder': 'Password', 'primaryauth.title': 'Sign In', 'forgotpassword': 'Forgot password?'}}, 'relayState': '/oauth2/v1/authorize/redirect?okta_key=fuBwvtRlO-qzfIogLHJ1c_69DrPCRiJVkUTh236O0YE', 'features': {'emailRecovery': True, 'restrictRedirectToForeground': True, 'deviceFingerprinting': True, 'consent': True, 'useDeviceFingerprintForSecurityImage': True, 'customExpiredPassword': True, 'router': True, 'showPasswordToggleOnSignInPage': True, 'securityImage': False, 'autoPush': True, 'smsRecovery': True, 'idpDiscovery': True, 'selfServiceUnlock': True, 'webauthn': True, 'showPasswordRequirementsAsHtmlList': True, 'registration': False, 'rememberMe': True, 'callRecovery': False, 'multiOptionalFactorEnroll': True}, 'baseUrl': 'https://prod.idp.collegeboard.org', 'assets': {'baseUrl': 'https://ok12static.oktacdn.com/assets/js/sdk/okta-signin-widget/5.9.4'}, 'customButtons': [], 'idpDiscovery': {'requestContext': '/oauth2/v1/authorize/redirect?okta_key=fuBwvtRlO-qzfIogLHJ1c_69DrPCRiJVkUTh236O0YE'}, 'logo': 'https://ok12static.oktacdn.com/fs/bco/1/fs03ir6072jIeBspy5d7', 'stateToken': '004NxJtd5R-tYk_oRjf7VNGgxP3-0vfEMlWgep5Ddb', 'helpLinks': {'help': 'https://support.collegeboard.org/help-center/account-help', 'forgotPassword': '', 'unlock': '', 'custom': []}, 'piv': {}}, 'accountChooserDiscoveryUrl': 'https://login.okta.com/discovery/iframe.html'}}'''

        self.__statetoken: str = self.__oktaData['signIn']['consent']["stateToken"]
        '''get okta login state token from oktaData'''

        self.__loginPayload = dumps({"password": self.__password,
                                     "username": self.__username,
                                     "options": {"warnBeforePasswordExpired": 'false',
                                                 "multiOptionalFactorEnroll": 'false'},
                                     "stateToken": self.__statetoken})
        '''JSON payload for logging in'''

        self.loginHeaders = dumps({"Accept": "application/json",
                                   "Content-Type": "application/json"})
        '''Headers that may need to be played with'''

        self.__loginRequest = self.__requestSession.post(url=self.__loginURL,
                                   data=self.__loginPayload,
                                   headers=self.__loginHeaders)
        '''Login, keep the request for later'''

    def __getLoginNonce(self):
        return self.__requestSession.post("https://prod.idp.collegeboard.org/api/v1/internal/device/nonce").json()[
            'nonce']
