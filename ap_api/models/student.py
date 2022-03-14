from requests import Response, session
import datetime
class Student:
    """Base class. Not for use with teacher accounts"""
    def __init__(self, apClassroomUser):
        self.user = apClassroomUser
        self.requestSession: session = apClassroomUser.requestSession

        self.initVariables()



    def initVariables(self):
        pass

    def getClasses(self):
        pass
        date = datetime.datetime.utcnow().isoformat().split('.')[0].replace("-",'').replace(":","")+"Z"

        finalRequestHeaders = {
            "x-amz-date": date

        }
        '''
        https://dgtkl2ep7natjmkbefhxflglie.appsync-api.us-east-1.amazonaws.com/graphql
        
        headers required:
        x-cb-catapult-authorization-token (From https://sucred.catapult-prod.collegeboard.org/rel/temp-user-aws-creds?cbEnv=pine&appId=366&cbAWSDomains=apfym,catapult&cacheNonce=0)
        x-cb-catapult-authentication-token == cb Login token (only the token) (cb login needed for sucred links)
        x-amz-security-token (From https://sucred.catapult-prod.collegeboard.org/rel/temp-user-aws-creds?cbEnv=pine&appId=366&cbAWSDomains=apfym,catapult&cacheNonce=0)
        authorization 
        x-amz-date (ISO 8601 format -- why can't they be normal and use unix epoch time?)
        
        "postData": {
            "mimeType": "application/json; charset=UTF-8",
            "params": [],
            "text": "{\"operationName\":\"getStudentEnrollments\",\"variables\":{\"code\":23},\"query\":\"query getStudentEnrollments($code: Int!) {\\n  getStudentEnrollments(educationPeriod: $code) {\\n    ...studentEnrollmentsFragment\\n    __typename\\n  }\\n}\\n\\nfragment studentEnrollmentsFragment on studentEnrollments {\\n  scoreSendData {\\n    diCode\\n    userPromptType\\n    __typename\\n  }\\n  courseEnrollments {\\n    ...enrollmentFragment\\n    __typename\\n  }\\n  __typename\\n}\\n\\nfragment enrollmentFragment on enrollment {\\n  orgName\\n  orgId\\n  courseName\\n  testCd\\n  sectionName\\n  sectionType\\n  teachers\\n  examIntent\\n  examStartTime\\n  examEndTime\\n  examWindow\\n  enrollmentId\\n  joinCode\\n  transferCode\\n  studentId\\n  studentOrTeacherCanChangeExamIntent\\n  registrationDeadline\\n  requiresUnlocking\\n  isPreAP\\n  isDigitalPortfolio\\n  isCapstone\\n  isStudioArt\\n  isDigitalExam\\n  address {\\n    city\\n    state\\n    country\\n    __typename\\n  }\\n  digitalApplicable\\n  accommodations\\n  appInstalled\\n  practiceStatus\\n  checkinStatus\\n  setupStatus\\n  examStatus\\n  makeupStatus\\n  isMakeupAvailable\\n  ...classroomFragment\\n  __typename\\n}\\n\\nfragment classroomFragment on enrollment {\\n  numResults\\n  numToComplete\\n  numToScore\\n  assignmentsLink\\n  resultsLink\\n  assignments {\\n    title\\n    startDate\\n    dueDate\\n    link\\n    __typename\\n  }\\n  __typename\\n}\\n\"}"
          }'''

        '''
        
        '''