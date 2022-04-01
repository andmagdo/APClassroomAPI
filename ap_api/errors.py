class AssignmentException(Exception):
    """
    Base exception for all assignment exceptions.
    """


class AssignmentNotFoundException(AssignmentException):
    """
    Exception for when an assignment is not found.
    """


class LoginException(Exception):
    """
    Exception for when a login fails.
    """


class InvalidCredentials(LoginException):
    """
    Exception for when the credentials are invalid.
    """


class InvalidPassword(LoginException):
    """
    Exception for when the password is invalid.
    """


class LockedOut(LoginException):
    """
    Exception for when the account is locked out.
    """

class RateLimitException(Exception):
    """
    Exception for when the rate limit is reached.
    """
