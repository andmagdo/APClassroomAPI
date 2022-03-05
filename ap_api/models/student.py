class Student:
    """Base class. Not for use with teacher accounts"""
    def __init__(self, student:dict, ):
        self.full_name: str = student.getName()


    def __str__(self) -> str:
        return f"{self.first_name} {self.last_name}"

    def __repr__(self) -> str:
        return f"{self.first_name} {self.last_name}"

    def getName(self):
        pass

