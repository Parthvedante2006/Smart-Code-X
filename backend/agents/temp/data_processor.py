from typing import List, Dict, Optional
from datetime import datetime

class DataValidator:
    def __init__(self, required_fields: List[str]):
        self.required_fields = required_fields
    
    def validate_record(self, record: Dict) -> tuple[bool, List[str]]:
        errors = []
        
        for field in self.required_fields:
            if field not in record or record[field] is None:
                errors.append(f"Missing required field: {field}")
        
        if 'email' in record and record['email']:
            if '@' not in record['email']:
                errors.append("Invalid email format")
        
        if 'age' in record and record['age']:
            if not (0 <= record['age'] <= 150):
                errors.append("Age must be between 0 and 150")
        
        return len(errors) == 0, errors

class DataTransformer:
    @staticmethod
    def normalize_text(field_value: str) -> str:
        if not field_value:
            return ""
        return field_value.strip().title()
    
    @staticmethod
    def calculate_age(birth_date: Optional[datetime]) -> Optional[int]:
        if not birth_date:
            return None
        
        today = datetime.now()
        age = today.year - birth_date.year
        
        if today.month < birth_date.month or (today.month == birth_date.month and today.day < birth_date.day):
            age -= 1
            
        return age