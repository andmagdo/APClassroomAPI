from requests import Response, session
from json import dumps


class profile:
    def __init__(self, apClassroomUser) -> None:
        self.initializeVariables()
        self.requestSession: session = apClassroomUser.requestSession
        self.user = apClassroomUser

        self.getProfileInfo(False)

    def getProfileInfo(self, verbose=True) -> None:
        """Get information about the logged in profile, by default getting all the info."""
        '''Need jwtToken for the extra info, get it from below, auth header looks like
                                                                            CBLogin 00000000-FFFF-0000-FFFF-000000000000
        https://sucred.catapult-prod.collegeboard.org/rel/temp-user-aws-creds?cbEnv=pine&appId=366&cbAWSDomains=catapult&cacheNonce={nonce}
        After some testing, the nonce is irrelevant, required, but can be set to 0'''

        '''auth header is sent from here as a cookie 
        (cb_login) https://account.collegeboard.org/login/exchangeToken?code={code}&state=cbAppDurl'''

        '''that site is redirected from here 
        (302 Found) https://prod.idp.collegeboard.org/login/step-up/redirect?stateToken={token}'''

        '''which comes from https://prod.idp.collegeboard.org/api/v1/authn'''

        '''We contacted authn as part of the login process, we can use that request for the info'''

        self.rawUserData: dict = self.user.loginRequest.json()
        self.firstName: str = self.rawUserData['_embedded']['user']['profile']['firstName']
        self.lastName: str = self.rawUserData['_embedded']['user']['profile']['lastName']
        self.email: str = self.rawUserData['_embedded']['user']['profile']['login']
        self.locale: str = self.rawUserData['_embedded']['user']['profile']['locale']
        self.timeZone: str = self.rawUserData['_embedded']['user']['profile']['timeZone']
        self.passwordChanged: str = self.rawUserData['_embedded']['user']['passwordChanged']
        '''When the password was last changed'''
        self.userId: str = self.rawUserData['_embedded']['user']['id']
        '''Probably not useful, but might as well be included'''
        if verbose:
            self.getMoreInfo()

    def getMoreInfo(self) -> None:
        """Get info that requires connection"""

        self.__stepUpUrl: str = self.rawUserData['_links']['next']['href']
        self.__stepUp: Response = self.requestSession.head(self.__stepUpUrl)
        if self.__stepUp.status_code != 302:
            self.user.updateLogin("https://account.collegeboard.org/login/login?idp=ECL&appId=400&DURL=https://my.collegeboard.org/profile/information")
            self.__stepUpUrl: str = self.rawUserData['_links']['next']['href']
            self.__stepUp: Response = self.requestSession.head(self.__stepUpUrl)

        self.__newUrl: str = self.__stepUp.headers['Location']

        self.__newUrlOut: Response = self.requestSession.get(self.__newUrl, allow_redirects=False)

        # TODO add cookies that are needed for the next request to session
        self.requestSession.cookies.set("oktaStateToken", self.user.stateToken)

        print(self.requestSession.cookies)


        self.__profileAuth:str = self.__newUrlOut.cookies.get('cb_login')
        # still nothin'


        self.__catapult: dict = self.requestSession.get(
            'https://sucred.catapult-prod.collegeboard.org/rel/temp-user-aws-creds?cbEnv=pine&appId=366&cbAWSDomains=catapult&cacheNonce=0',
            headers={'Authorization': 'CBLogin ' + self.__profileAuth}).json()

        self.username: str = self.__catapult['cbUserProfile']['sessionInfo']['identityKey']['userName']
        '''Because the username (now no longer used) is an advanced feature'''
        self.__jwtToken: str = self.__catapult['cbJwtToken']

        self.infoUrl: str = 'https://lambda.us-east-1.amazonaws.com/2015-03-31/functions/mycb-mfe-profile-api-user-lambda-prod/invocations'

        self.__loginPayload: dict = dumps({'eventData': {'jwtToken': self.__jwtToken, 'sessionId': self.__profileAuth},
                                           'eventType': 'retrieve-student-profile-information'})
        '''Yes, it uses authorization and ids interchangeably'''

        self.__infoRequest: Response = self.requestSession.post(self.infoUrl)
        self.infoRequest: dict = self.__infoRequest.json()
        self.legalFirstName: str = self.infoRequest['firstName']
        self.middleInitial: str = self.infoRequest['middleInitial']
        self.genderCode: str = self.infoRequest['genderCode']
        self.genderText: str = self.infoRequest['genderText']
        self.graduationDate: str = self.infoRequest['graduationDate']
        self.graduationYear: str = self.infoRequest['cohort']
        self.schoolCode: str = self.infoRequest['schoolCode']
        self.schoolName: str = self.infoRequest['schoolName']
        self.schoolType: str = self.infoRequest['schoolType']
        self.addressLine1: str = self.infoRequest['addressLine1']
        self.addressLine2: str = self.infoRequest['addressLine2']
        self.addressLine3: str = self.infoRequest['addressLine3']
        self.state: str = self.infoRequest['state']
        self.city: str = self.infoRequest['city']
        self.zipCode: str = self.infoRequest['zipCode']
        self.province: str = self.infoRequest['province']
        self.countryCode: str = self.infoRequest['countryCode']
        self.internationalPostalCode: str = self.infoRequest['internationalPostalCode']
        self.addressType: str = self.infoRequest['addressType']
        self.phoneCountryCode: str = self.infoRequest['phoneCountryCode']
        self.phoneNdc: str = self.infoRequest['phoneNdc']
        self.phoneLocal: str = self.infoRequest['phoneLocal']
        self.phoneNumber: str = self.phoneNdc + self.phoneLocal
        self.textMessageAllowed: str = self.infoRequest['textMessageAllowed']
        self.internationalPhone: str = self.infoRequest['internationalPhone']

        self.rawUserData |= self.infoRequest
        '''combine the dictionaries'''

    def initializeVariables(self) -> None:
        """Init Variables so that errors do not occur"""
        self.rawUserData: dict = {}
        self.firstName: str = ''
        self.lastName: str = ''
        self.email: str = ''
        self.locale: str = ''
        self.timeZone: str = ''
        self.passwordChanged: str = ''
        self.userId: str = ''
        self.__stepUpUrl: str = ''
        self.__stepUp = None

        self.__newUrl: str = ''
        self.__newUrlOut = None
        self.__profileAuth: str = ''
        self.__catapult: dict = {}
        self.username: str = ''
        self.__jwtToken: str = ''

        self.infoUrl: str = ''

        self.__loginPayload: dict = {}

        self.__infoRequest = None
        self.infoRequest: dict = {}
        self.legalFirstName: str = ''
        self.middleInitial: str = ''
        self.genderCode: str = ''
        self.genderText: str = ''
        self.graduationDate: str = ''
        self.graduationYear: str = ''
        self.schoolCode: str = ''
        self.schoolName: str = ''
        self.schoolType: str = ''
        self.addressLine1: str = ''
        self.addressLine2: str = ''
        self.addressLine3: str = ''
        self.state: str = ''
        self.city: str = ''
        self.zipCode: str = ''
        self.province: str = ''
        self.countryCode: str = ''
        self.internationalPostalCode: str = ''
        self.addressType: str = ''
        self.phoneCountryCode: str = ''
        self.phoneNdc: str = ''
        self.phoneLocal: str = ''
        self.phoneNumber: str = ''
        self.textMessageAllowed: str = ''
        self.internationalPhone: str = ''
