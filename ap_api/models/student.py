class Student:
    """Base class. Not for use with teacher accounts"""
    def __init__(self, student:dict, ):
        self.first_name: str = student.get("first_name")
        self.last_name: str = student.get("last_name")

    def __str__(self) -> str:
        return f"{self.first_name} {self.last_name}"

    def __repr__(self) -> str:
        return f"{self.first_name} {self.last_name}"


