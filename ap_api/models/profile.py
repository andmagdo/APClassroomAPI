class profile:
    def __init__(self, apClassroomUser):
        self.requestSession = apClassroomUser.requestSession
        self.user = apClassroomUser

    def getProfileInfo(self, verbose=False):
        '''Need jwtToken, get it from below, auth header looks like CBLogin 00000000-FFFF-0000-FFFF-000000000000'''
        '''https://sucred.catapult-prod.collegeboard.org/rel/temp-user-aws-creds?cbEnv=pine&appId=366&cbAWSDomains=catapult&cacheNonce={nonce}'''

        '''auth header is sent from here as a cookie (cb_login) https://account.collegeboard.org/login/exchangeToken?code={code}&state=cbAppDurl'''

        '''that site is redirected from here (302 Found) https://prod.idp.collegeboard.org/login/step-up/redirect?stateToken={token}'''

        '''which comes from https://prod.idp.collegeboard.org/api/v1/authn'''

        '''We contacted authn as part of the login process, we can use that request for the info'''

        self.rawUserData:    dict = self.user.loginRequest.json()
        self.firstName:       str = self.rawUserData['_embedded']['user']['profile']['firstName']
        self.lastName:        str = self.rawUserData['_embedded']['user']['profile']['lastName']
        self.email:           str = self.rawUserData['_embedded']['user']['profile']['login']
        self.locale:          str = self.rawUserData['_embedded']['user']['profile']['locale']
        self.timeZone:        str = self.rawUserData['_embedded']['user']['profile']['timeZone']
        self.passwordChanged: str = self.rawUserData['_embedded']['user']['passwordChanged']
        '''When the password was last changed'''
        self.userId:          str = self.rawUserData['_embedded']['user']['id']
        '''Probably not useful, but might as well be included'''
        if verbose:
            self.getMoreInfo()

    def getMoreInfo(self):
        pass
        #self.__stepUpRedirect =
        #if self.__stepUpRedirect.status_code != 302:
        #    self.user.login()

