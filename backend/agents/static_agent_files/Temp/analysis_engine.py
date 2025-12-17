from typing import List, Dict, Any
from data_processor import DataValidator, DataTransformer

class AnalysisEngine:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        required_fields = config.get('required_fields', ['name', 'email'])
        self.validator = DataValidator(required_fields)
        self.transformer = DataTransformer()
    
    def process_dataset(self, dataset: List[Dict]) -> Dict[str, Any]:
        valid_records = []
        invalid_records = []
        analysis_results = {
            'total_records': len(dataset),
            'valid_count': 0,
            'invalid_count': 0,
            'insights': {}
        }
        
        for record in dataset:
            is_valid, errors = self.validator.validate_record(record)
            
            if is_valid:
                processed_record = self._enhance_record(record)
                valid_records.append(processed_record)
            else:
                invalid_records.append({
                    'record': record,
                    'errors': errors
                })
        
        analysis_results['valid_count'] = len(valid_records)
        analysis_results['invalid_count'] = len(invalid_records)
        analysis_results['insights'] = self._generate_insights(valid_records)
        
        return analysis_results
    
    def _enhance_record(self, record: Dict) -> Dict:
        enhanced = record.copy()
        
        if 'name' in enhanced:
            enhanced['normalized_name'] = self.transformer.normalize_text(enhanced['name'])
        
        return enhanced
    
    def _generate_insights(self, valid_records: List[Dict]) -> Dict[str, Any]:
        if not valid_records:
            return {}
        
        insights = {
            'record_count': len(valid_records),
            'field_statistics': {}
        }
        
        all_fields = set()
        for record in valid_records:
            all_fields.update(record.keys())
        
        for field in all_fields:
            field_presence = sum(1 for record in valid_records if field in record and record[field] is not None)
            insights['field_statistics'][field] = {
                'presence_count': field_presence,
                'presence_percentage': round((field_presence / len(valid_records)) * 100, 2)
            }
        
        return insights