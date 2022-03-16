from requests import Session, Response
from .login import updateLogin


def getCbLogin(user) -> str:
    session: Session = user.requestSession
    stepUrl: str = user.loginRequest.json()['_links']['next']['href']
    stepUp: Response = session.head(stepUrl)
    if stepUp.status_code != 302:
        updateLogin(user)
        # stepUpUrl: str = self.rawUserData['_links']['next']['href']
        # stepUp: Response = self.requestSession.head(self.__stepUpUrl)
